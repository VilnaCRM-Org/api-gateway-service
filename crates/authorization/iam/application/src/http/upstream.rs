//! REST handlers of the upstreams of the gateway configuration, and the use-case calls that the
//! GraphQL resolvers share.
//!
//! A handler takes the IAM state and the problem-aware extractors only (`ApiPath`,
//! `ValidatedQuery`, `ValidatedJson`, the IAM extractors `CallerPrincipal` and
//! `IdempotencyKeyHeader`, `PreferWaitHeader`); the test of the `handler` module checks every
//! handler against that rule.

pub mod dto;

use axum::Json;
use axum::extract::State;
use axum::http::header::ETAG;
use axum::http::{HeaderName, StatusCode};
use iam_domain::{
    ActorRef, ChangeId, ChangeReceipt, IdempotencyKey, IdempotencyRequest, UpstreamId,
    UpstreamParts, UpstreamSettingsDraft,
};
use shared_application::http::{ApiPath, Problem, ValidatedJson, ValidatedQuery, Violation};

use super::IamState;
use super::extract::{
    CallerPrincipal, IdempotencyKeyHeader, PreferWaitHeader, VersionedWriteHeaders,
};
use super::response::{WriteHeaders, change_headers, created_headers, etag, write_status};
use super::user_role::find_replay;
use crate::command::create_upstream::CreateUpstreamCommand;
use crate::command::delete_upstream::DeleteUpstreamCommand;
use crate::command::update_upstream::UpdateUpstreamCommand;
use crate::error::IamError;
use crate::principal::Principal;
use crate::query::get_change_receipt::GetChangeReceiptQuery;
use crate::query::get_upstream::GetUpstreamQuery;
use crate::query::list_upstreams::UpstreamPage;
use dto::{
    CreateUpstreamRequest, ListUpstreamsParams, UpdateUpstreamRequest, UpstreamPageResponse,
    UpstreamResponse, delete_upstream_canonical_form,
};

/// The path of the upstream collection, under which a created upstream has its `Location`.
const UPSTREAMS_PATH: &str = "/api/upstreams";

/// The upstream id of a path or an argument.
///
/// # Errors
///
/// [`IamError::Invalid`] with a violation of `id` when the text is not a UUID.
pub(crate) fn parse_upstream_id(text: &str) -> Result<UpstreamId, IamError> {
    UpstreamId::parse(text).map_err(|_error| {
        IamError::Invalid(vec![Violation {
            property_path: "id".to_owned(),
            message: "This value is not a valid UUID.".to_owned(),
            code: "uuid".to_owned(),
        }])
    })
}

/// Creates an upstream as `caller`, or replays the creation that `key` already committed; REST and
/// GraphQL share it.
///
/// The upstream and the receipt of the change are read back, because a command returns no data.
///
/// # Errors
///
/// The problem of a refused request: 403 for a caller without the route key of the catalogue
/// service, 409 for a duplicate name or an upstream of the `iam` service, 422 for invalid fields
/// or a key reused for another request, 500 for a storage failure.
pub(crate) async fn create_upstream(
    state: &IamState,
    caller: &Principal,
    key: Option<IdempotencyKey>,
    request: CreateUpstreamRequest,
) -> Result<(UpstreamParts, ChangeReceipt), Problem> {
    let actor = caller.actor();
    let idempotency = key.map(|key| IdempotencyRequest {
        key,
        request_digest: state.request_digester.digest(&request.canonical_form()),
    });
    if let Some(replayed) = find_replay(state, &actor, idempotency.as_ref()).await? {
        return read_created(state, replayed).await;
    }
    let change_id = ChangeId::from_uuid(state.uuid_generator.generate());
    let upstream_id = UpstreamId::from_uuid(state.uuid_generator.generate());
    let command = create_command(change_id, upstream_id, actor, idempotency, request);
    state.command_bus.dispatch(command).await?;
    let receipt = state
        .query_bus
        .ask(GetChangeReceiptQuery { change_id })
        .await?;
    read_created(state, receipt).await
}

/// The command that creates the upstream of the request.
fn create_command(
    change_id: ChangeId,
    upstream_id: UpstreamId,
    actor: ActorRef,
    idempotency: Option<IdempotencyRequest>,
    request: CreateUpstreamRequest,
) -> CreateUpstreamCommand {
    CreateUpstreamCommand {
        change_id,
        upstream_id,
        actor,
        name: request.name,
        settings: UpstreamSettingsDraft {
            namespace: request.namespace,
            service_name: request.service,
            catalog_service: request.catalog_service,
            port: request.port,
            protocol: request.protocol.into(),
            forward_credentials: request.forward_credentials,
            connect_timeout_ms: request.connect_timeout_ms,
            response_timeout_ms: request.response_timeout_ms,
            concurrency_limit: request.concurrency_limit,
            retry_budget_percent: request.retry_budget_percent,
            outlier_threshold: request.outlier_consecutive_errors,
        },
        idempotency,
    }
}

/// The upstream that the receipt of a creation names.
async fn read_created(
    state: &IamState,
    receipt: ChangeReceipt,
) -> Result<(UpstreamParts, ChangeReceipt), Problem> {
    let id = UpstreamId::parse(receipt.target().target_id()).map_err(IamError::from)?;
    let upstream = find_upstream(state, id).await?.ok_or(IamError::NotFound)?;
    Ok((upstream, receipt))
}

/// Updates the upstream `id` as `caller` when it still holds the version `expected`, or replays
/// the update that `key` already committed; REST and GraphQL share it.
///
/// The receipt of the change and the upstream are read back, because a command returns no data.
///
/// # Errors
///
/// The problem of a refused request: 403 for a caller without the route key of the catalogue
/// service, 404 for an unknown upstream, 409 for a concurrent change or an upstream that IAM
/// manages itself, 412 for a stale version, 422 for invalid fields, a new name or a key reused for
/// another request, 500 for a storage failure.
pub(crate) async fn update_upstream(
    state: &IamState,
    caller: &Principal,
    id: UpstreamId,
    headers: VersionedWriteHeaders,
    request: UpdateUpstreamRequest,
) -> Result<(UpstreamParts, ChangeReceipt), Problem> {
    let VersionedWriteHeaders { expected, key } = headers;
    let actor = caller.actor();
    let idempotency = key.map(|key| IdempotencyRequest {
        key,
        request_digest: state
            .request_digester
            .digest(&request.canonical_form(id, expected)),
    });
    let receipt = if let Some(replayed) = find_replay(state, &actor, idempotency.as_ref()).await? {
        replayed
    } else {
        let change_id = ChangeId::from_uuid(state.uuid_generator.generate());
        let command = UpdateUpstreamCommand {
            change_id,
            upstream_id: id,
            actor,
            expected,
            patch: request.into_patch(),
            idempotency,
        };
        state.command_bus.dispatch(command).await?;
        state
            .query_bus
            .ask(GetChangeReceiptQuery { change_id })
            .await?
    };
    let upstream = find_upstream(state, id).await?.ok_or(IamError::NotFound)?;
    Ok((upstream, receipt))
}

/// Deletes the upstream `id` as `caller` when it still holds the version `expected` and no route
/// references it, or replays the deletion that `key` already committed; REST and GraphQL share it.
///
/// It returns the receipt of the change, because a command returns no data and a deleted upstream
/// can no longer be read.
///
/// # Errors
///
/// The problem of a refused request: 403 for a caller without the route key of the catalogue
/// service, 404 for an unknown or deleted upstream, 409 for a route that references the upstream,
/// a concurrent change or an upstream that IAM manages itself, 412 for a stale version, 422 for a
/// key reused for another request, 500 for a storage failure.
pub(crate) async fn delete_upstream(
    state: &IamState,
    caller: &Principal,
    id: UpstreamId,
    headers: VersionedWriteHeaders,
) -> Result<ChangeReceipt, Problem> {
    let VersionedWriteHeaders { expected, key } = headers;
    let actor = caller.actor();
    let idempotency = key.map(|key| IdempotencyRequest {
        key,
        request_digest: state
            .request_digester
            .digest(&delete_upstream_canonical_form(id, expected)),
    });
    if let Some(replayed) = find_replay(state, &actor, idempotency.as_ref()).await? {
        return Ok(replayed);
    }
    let change_id = ChangeId::from_uuid(state.uuid_generator.generate());
    let command = DeleteUpstreamCommand {
        change_id,
        upstream_id: id,
        actor,
        expected,
        idempotency,
    };
    state.command_bus.dispatch(command).await?;
    Ok(state
        .query_bus
        .ask(GetChangeReceiptQuery { change_id })
        .await?)
}

/// The upstream with the identifier, none when it is unknown or deleted.
///
/// # Errors
///
/// The 500 problem of a storage failure.
pub(crate) async fn find_upstream(
    state: &IamState,
    id: UpstreamId,
) -> Result<Option<UpstreamParts>, Problem> {
    Ok(state.query_bus.ask(GetUpstreamQuery { id }).await?)
}

/// One page of upstreams for validated parameters.
///
/// # Errors
///
/// The 422 problem of an invalid cursor, the 500 problem of a storage failure.
pub(crate) async fn list_upstreams(
    state: &IamState,
    params: ListUpstreamsParams,
) -> Result<UpstreamPage, Problem> {
    Ok(state.query_bus.ask(params.into_query()?).await?)
}

/// Creates an upstream.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without the route key of the catalogue
/// service, 409 for a duplicate name or an upstream of the `iam` service, 422 for invalid fields
/// or a reused idempotency key, 500 when the storage fails.
#[utoipa::path(
    post,
    path = "/upstreams",
    operation_id = "api_upstreams_post",
    tag = "iam",
    summary = "Creates an upstream.",
    description = "Registers a Kubernetes Service that the gateway proxies to at version 1, writes its `upstream/<name>` state record, takes the next policy version and records `iam.upstream.created`. The caller needs `iam:route:{catalogService}` or `iam:route:*`; an upstream of the `iam` service is refused with 409 `system-entry`. A repeated `Idempotency-Key` with the same body within 24 hours returns the original result.",
    security(("bearerAuth" = [])),
    params(("Idempotency-Key" = Option<String>, Header, description = "Makes the creation safe to repeat for 24 hours; 1 to 255 visible ASCII characters."),
        ("Prefer" = Option<String>, Header, description = "What the write waits for: `wait=published` (the default) returns once Kafka acknowledged the policy version, `wait=propagated` is refused with 422 until the gateway pods report their versions.")),
    request_body(content = CreateUpstreamRequest, content_type = "application/json"),
    responses(
        (
            status = 201,
            description = "The upstream was created.",
            body = UpstreamResponse,
            headers(
                ("location" = String, description = "Path of the created upstream."),
                ("etag" = String, description = "The version of the upstream in double quotes."),
                ("iam-policy-version" = String, description = "The policy version that the change produced."),
                ("iam-policy-offset" = String, description = "The offset at which Kafka stored the `__head` record of the policy version; present when the change was acknowledged.")
            )
        ),
        (
            status = 202,
            description = "The change is committed and its policy version was not acknowledged by Kafka within `PUBLISH_WAIT_TIMEOUT`; it may not be in force on the gateway yet.",
            body = UpstreamResponse,
            headers(
                ("location" = String, description = "Path of the created upstream."),
                ("etag" = String, description = "The version of the upstream in double quotes."),
                ("iam-policy-version" = String, description = "The policy version that the change produced."),
                ("iam-propagation-status" = String, description = "`committed_pending_propagation`.")
            )
        ),
        (status = 400, description = "Invalid input.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 403, description = "The caller lacks the operation key or the route key of the catalogue service.", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "An upstream with this name exists, or the upstream belongs to the `iam` service.", body = Problem, content_type = "application/problem+json"),
        (status = 413, description = "Request body too large.", body = Problem, content_type = "application/problem+json"),
        (status = 415, description = "Unsupported media type.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed, or the idempotency key was used for another request.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn create(
    State(state): State<IamState>,
    CallerPrincipal(caller): CallerPrincipal,
    IdempotencyKeyHeader(key): IdempotencyKeyHeader,
    PreferWaitHeader(_mode): PreferWaitHeader,
    ValidatedJson(body): ValidatedJson<CreateUpstreamRequest>,
) -> Result<(StatusCode, WriteHeaders, Json<UpstreamResponse>), Problem> {
    let (upstream, receipt) = create_upstream(&state, &caller, key, body).await?;
    let headers = created_headers(&receipt, UPSTREAMS_PATH);
    Ok((
        write_status(&receipt, StatusCode::CREATED),
        headers,
        Json(UpstreamResponse::from(upstream)),
    ))
}

/// Reads an upstream.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without the operation key, 404 for an
/// unknown upstream, 422 for an id that is not a UUID.
#[utoipa::path(
    get,
    path = "/upstreams/{id}",
    operation_id = "api_upstreams_id_get",
    tag = "iam",
    summary = "Retrieves an upstream.",
    description = "Returns the upstream with the identifier, with its `ETag`.",
    security(("bearerAuth" = [])),
    params(("id" = String, Path, format = Uuid, description = "Upstream identifier")),
    responses(
        (
            status = 200,
            description = "The upstream.",
            body = UpstreamResponse,
            headers(("etag" = String, description = "The version of the upstream in double quotes."))
        ),
        (status = 400, description = "Invalid identifier.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 403, description = "The caller lacks the operation key.", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Upstream not found.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn get_one(
    State(state): State<IamState>,
    CallerPrincipal(_caller): CallerPrincipal,
    ApiPath(id): ApiPath<String>,
) -> Result<([(HeaderName, String); 1], Json<UpstreamResponse>), Problem> {
    let upstream = find_upstream(&state, parse_upstream_id(&id)?)
        .await?
        .ok_or(IamError::NotFound)?;
    let tag = etag(upstream.version);
    Ok(([(ETAG, tag)], Json(UpstreamResponse::from(upstream))))
}

/// Updates an upstream.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without the route key of the catalogue
/// service, 404 for an unknown upstream, 409 for a system upstream, 412 for a stale `If-Match`,
/// 422 for invalid fields, a new name or a reused idempotency key, 428 without `If-Match`, 500
/// when the storage fails.
#[utoipa::path(
    patch,
    path = "/upstreams/{id}",
    operation_id = "api_upstreams_id_patch",
    tag = "iam",
    summary = "Updates an upstream.",
    description = "Changes the settings named in the body when `If-Match` holds the current `ETag`, increases the version, writes the `upstream/<name>` state record, takes the next policy version and records `iam.upstream.updated`. The name cannot change. The caller needs `iam:route:{catalogService}` or `iam:route:*` for the service before and after the change; a system upstream and one of the `iam` service are refused with 409 `system-entry`. A repeated `Idempotency-Key` with the same request within 24 hours returns the original result.",
    security(("bearerAuth" = [])),
    params(
        ("id" = String, Path, format = Uuid, description = "Upstream identifier"),
        ("If-Match" = String, Header, description = "The `ETag` of the version the update changes, such as `\"3\"`."),
        ("Idempotency-Key" = Option<String>, Header, description = "Makes the update safe to repeat for 24 hours; 1 to 255 visible ASCII characters."),
        ("Prefer" = Option<String>, Header, description = "What the write waits for: `wait=published` (the default) returns once Kafka acknowledged the policy version, `wait=propagated` is refused with 422 until the gateway pods report their versions.")
    ),
    request_body(content = UpdateUpstreamRequest, content_type = "application/json"),
    responses(
        (
            status = 200,
            description = "The upstream was updated.",
            body = UpstreamResponse,
            headers(
                ("etag" = String, description = "The new version of the upstream in double quotes."),
                ("iam-policy-version" = String, description = "The policy version that the change produced."),
                ("iam-policy-offset" = String, description = "The offset at which Kafka stored the `__head` record of the policy version; present when the change was acknowledged.")
            )
        ),
        (
            status = 202,
            description = "The change is committed and its policy version was not acknowledged by Kafka within `PUBLISH_WAIT_TIMEOUT`; it may not be in force on the gateway yet.",
            body = UpstreamResponse,
            headers(
                ("etag" = String, description = "The new version of the upstream in double quotes."),
                ("iam-policy-version" = String, description = "The policy version that the change produced."),
                ("iam-propagation-status" = String, description = "`committed_pending_propagation`.")
            )
        ),
        (status = 400, description = "Invalid input.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 403, description = "The caller lacks the operation key or the route key of the catalogue service.", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Upstream not found.", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The upstream is a system upstream or belongs to the `iam` service, or it changed concurrently.", body = Problem, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is not the current version.", body = Problem, content_type = "application/problem+json"),
        (status = 413, description = "Request body too large.", body = Problem, content_type = "application/problem+json"),
        (status = 415, description = "Unsupported media type.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed, the name changed, or the idempotency key was used for another request.", body = Problem, content_type = "application/problem+json"),
        (status = 428, description = "`If-Match` is missing.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn update(
    State(state): State<IamState>,
    CallerPrincipal(caller): CallerPrincipal,
    ApiPath(id): ApiPath<String>,
    headers: VersionedWriteHeaders,
    ValidatedJson(body): ValidatedJson<UpdateUpstreamRequest>,
) -> Result<(StatusCode, WriteHeaders, Json<UpstreamResponse>), Problem> {
    let (upstream, receipt) =
        update_upstream(&state, &caller, parse_upstream_id(&id)?, headers, body).await?;
    Ok((
        write_status(&receipt, StatusCode::OK),
        change_headers(&receipt),
        Json(UpstreamResponse::from(upstream)),
    ))
}

/// Deletes an upstream.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without the route key of the catalogue
/// service, 404 for an unknown upstream, 409 for a referenced or system upstream, 412 for a stale
/// `If-Match`, 422 for an id that is not a UUID or a reused idempotency key, 428 without
/// `If-Match`, 500 when the storage fails.
#[utoipa::path(
    delete,
    path = "/upstreams/{id}",
    operation_id = "api_upstreams_id_delete",
    tag = "iam",
    summary = "Deletes an upstream.",
    description = "Deletes the upstream when `If-Match` holds the current `ETag` and no route references it: it leaves the listings at once, its `upstream/<name>` state record becomes a tombstone, the next policy version is committed, and `iam.upstream.deleted` and an audit record are written in the same transaction. The caller needs `iam:route:{catalogService}` or `iam:route:*`; a system upstream and one of the `iam` service are refused with 409 `system-entry`, and an upstream that a route references with 409 `referenced-by-route`. A repeated `Idempotency-Key` with the same request within 24 hours returns the original result.",
    security(("bearerAuth" = [])),
    params(
        ("id" = String, Path, format = Uuid, description = "Upstream identifier"),
        ("If-Match" = String, Header, description = "The `ETag` of the version the deletion ends, such as `\"3\"`."),
        ("Idempotency-Key" = Option<String>, Header, description = "Makes the deletion safe to repeat for 24 hours; 1 to 255 visible ASCII characters."),
        ("Prefer" = Option<String>, Header, description = "What the write waits for: `wait=published` (the default) returns once Kafka acknowledged the policy version, `wait=propagated` is refused with 422 until the gateway pods report their versions.")
    ),
    responses(
        (
            status = 204,
            description = "The upstream was deleted.",
            headers(
                ("etag" = String, description = "The final version of the upstream in double quotes."),
                ("iam-policy-version" = String, description = "The policy version that the change produced."),
                ("iam-policy-offset" = String, description = "The offset at which Kafka stored the `__head` record of the policy version; present when the change was acknowledged.")
            )
        ),
        (
            status = 202,
            description = "The change is committed and its policy version was not acknowledged by Kafka within `PUBLISH_WAIT_TIMEOUT`; it may not be in force on the gateway yet.",
            headers(
                ("etag" = String, description = "The final version of the upstream in double quotes."),
                ("iam-policy-version" = String, description = "The policy version that the change produced."),
                ("iam-propagation-status" = String, description = "`committed_pending_propagation`.")
            )
        ),
        (status = 400, description = "Invalid identifier.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 403, description = "The caller lacks the operation key or the route key of the catalogue service.", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Upstream not found.", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "A route references the upstream, the upstream is a system upstream or belongs to the `iam` service, or it changed concurrently.", body = Problem, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is not the current version.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed, or the idempotency key was used for another request.", body = Problem, content_type = "application/problem+json"),
        (status = 428, description = "`If-Match` is missing.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn delete(
    State(state): State<IamState>,
    CallerPrincipal(caller): CallerPrincipal,
    ApiPath(id): ApiPath<String>,
    headers: VersionedWriteHeaders,
) -> Result<(StatusCode, WriteHeaders), Problem> {
    let receipt = delete_upstream(&state, &caller, parse_upstream_id(&id)?, headers).await?;
    Ok((
        write_status(&receipt, StatusCode::NO_CONTENT),
        change_headers(&receipt),
    ))
}

/// Lists upstreams.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without the operation key, 422 for invalid
/// parameters.
#[utoipa::path(
    get,
    path = "/upstreams",
    operation_id = "api_upstreams_get",
    tag = "iam",
    summary = "Retrieves the collection of upstreams.",
    description = "Returns one page of the upstreams that are not deleted in a stable order, with the `nextCursor` of the next page.",
    security(("bearerAuth" = [])),
    params(ListUpstreamsParams),
    responses(
        (status = 200, description = "One page of upstreams.", body = UpstreamPageResponse),
        (status = 400, description = "Invalid query parameter.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 403, description = "The caller lacks the operation key.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn list(
    State(state): State<IamState>,
    CallerPrincipal(_caller): CallerPrincipal,
    ValidatedQuery(params): ValidatedQuery<ListUpstreamsParams>,
) -> Result<Json<UpstreamPageResponse>, Problem> {
    Ok(Json(UpstreamPageResponse::from(
        list_upstreams(&state, params).await?,
    )))
}

#[cfg(test)]
mod tests;
