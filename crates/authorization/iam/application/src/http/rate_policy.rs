//! REST handlers of the IAM rate policies, and the use-case calls that the GraphQL resolvers share
//! (FR-64).
//!
//! A handler takes the IAM state and the problem-aware extractors only (`ApiPath`,
//! `ValidatedQuery`, `ValidatedJson`, the IAM extractors `CallerPrincipal`, `IdempotencyKeyHeader`,
//! `VersionedWriteHeaders` and `PreferWaitHeader`); the test of the `handler` module checks every
//! handler against that rule.

pub mod dto;

use axum::Json;
use axum::extract::State;
use axum::http::header::ETAG;
use axum::http::{HeaderName, StatusCode};
use iam_domain::{
    ActorRef, ChangeId, ChangeReceipt, IdempotencyKey, IdempotencyRequest, RatePolicyId,
    RatePolicyParts,
};
use shared_application::http::{ApiPath, Problem, ValidatedJson, ValidatedQuery, Violation};

use self::dto::{
    CreateRatePolicyRequest, DeleteRatePolicyResponse, ListRatePoliciesParams,
    RatePolicyPageResponse, RatePolicyResponse, UpdateRatePolicyRequest,
    delete_rate_policy_canonical_form,
};
use super::IamState;
use super::extract::{
    CallerPrincipal, IdempotencyKeyHeader, PreferWaitHeader, VersionedWriteHeaders,
};
use super::response::{WriteHeaders, change_headers, created_headers, etag, write_status};
use crate::command::create_rate_policy::CreateRatePolicyCommand;
use crate::command::delete_rate_policy::DeleteRatePolicyCommand;
use crate::command::update_rate_policy::UpdateRatePolicyCommand;
use crate::error::IamError;
use crate::principal::Principal;
use crate::query::get_change_receipt::GetChangeReceiptQuery;
use crate::query::get_idempotent_replay::GetIdempotentReplayQuery;
use crate::query::get_rate_policy::GetRatePolicyQuery;
use crate::query::list_rate_policies::RatePolicyPage;

/// The path of the rate-policy collection, under which a created rate policy has its `Location`.
const RATE_POLICIES_PATH: &str = "/api/rate-policies";

/// The rate policy id of a path or an argument.
///
/// # Errors
///
/// [`IamError::Invalid`] with a violation of `id` when the text is not a UUID.
pub(crate) fn parse_rate_policy_id(text: &str) -> Result<RatePolicyId, IamError> {
    RatePolicyId::parse(text).map_err(|_error| {
        IamError::Invalid(vec![Violation {
            property_path: "id".to_owned(),
            message: "This value is not a valid UUID.".to_owned(),
            code: "uuid".to_owned(),
        }])
    })
}

/// The receipt of the change that the key already committed for the same request, if any.
async fn find_replay(
    state: &IamState,
    actor: &ActorRef,
    idempotency: Option<&IdempotencyRequest>,
) -> Result<Option<ChangeReceipt>, Problem> {
    let Some(request) = idempotency else {
        return Ok(None);
    };
    let query = GetIdempotentReplayQuery {
        actor: actor.clone(),
        request: request.clone(),
    };
    Ok(state.query_bus.ask(query).await?)
}

/// Creates a rate policy as `caller`, or replays the creation that `key` already committed; REST
/// and GraphQL share it.
///
/// The rate policy and the receipt of the change are read back, because a command returns no data.
///
/// # Errors
///
/// The problem of a refused request: 422 for invalid fields or a key reused for another request,
/// 409 for a duplicate name, 500 for a storage failure.
pub(crate) async fn create_rate_policy(
    state: &IamState,
    caller: &Principal,
    key: Option<IdempotencyKey>,
    request: CreateRatePolicyRequest,
) -> Result<(RatePolicyParts, ChangeReceipt), Problem> {
    let actor = caller.actor();
    let form = request.canonical_form();
    let idempotency = key.map(|key| IdempotencyRequest {
        key,
        request_digest: state.request_digester.digest(&form),
    });
    if let Some(replayed) = find_replay(state, &actor, idempotency.as_ref()).await? {
        return read_created(state, replayed).await;
    }
    let change_id = ChangeId::from_uuid(state.uuid_generator.generate());
    let command = CreateRatePolicyCommand {
        change_id,
        rate_policy_id: RatePolicyId::from_uuid(state.uuid_generator.generate()),
        actor,
        values: request.into_values()?,
        idempotency,
    };
    state.command_bus.dispatch(command).await?;
    let receipt = state
        .query_bus
        .ask(GetChangeReceiptQuery { change_id })
        .await?;
    read_created(state, receipt).await
}

/// The rate policy that the receipt of a creation names.
async fn read_created(
    state: &IamState,
    receipt: ChangeReceipt,
) -> Result<(RatePolicyParts, ChangeReceipt), Problem> {
    let id = RatePolicyId::parse(receipt.target().target_id()).map_err(IamError::from)?;
    let policy = find_rate_policy(state, id)
        .await?
        .ok_or(IamError::NotFound)?;
    Ok((policy, receipt))
}

/// Updates the rate policy `id` as `caller` when it still holds the version `expected`, or replays
/// the update that `key` already committed; REST and GraphQL share it.
///
/// The receipt of the change and the rate policy are read back, because a command returns no data.
///
/// # Errors
///
/// The problem of a refused request: 404 for an unknown rate policy, 409 for a duplicate name or a
/// concurrent change, 412 for a stale version, 422 for invalid fields or a key reused for another
/// request, 428 without a version, 500 for a storage failure.
pub(crate) async fn update_rate_policy(
    state: &IamState,
    caller: &Principal,
    id: RatePolicyId,
    headers: VersionedWriteHeaders,
    request: UpdateRatePolicyRequest,
) -> Result<(RatePolicyParts, ChangeReceipt), Problem> {
    let VersionedWriteHeaders { expected, key } = headers;
    let actor = caller.actor();
    let form = request.canonical_form(id, expected);
    let idempotency = key.map(|key| IdempotencyRequest {
        key,
        request_digest: state.request_digester.digest(&form),
    });
    let receipt = if let Some(replayed) = find_replay(state, &actor, idempotency.as_ref()).await? {
        replayed
    } else {
        let change_id = ChangeId::from_uuid(state.uuid_generator.generate());
        let command = UpdateRatePolicyCommand {
            change_id,
            rate_policy_id: id,
            actor,
            expected,
            patch: request.into_patch()?,
            idempotency,
        };
        state.command_bus.dispatch(command).await?;
        state
            .query_bus
            .ask(GetChangeReceiptQuery { change_id })
            .await?
    };
    let policy = find_rate_policy(state, id)
        .await?
        .ok_or(IamError::NotFound)?;
    Ok((policy, receipt))
}

/// Deletes the rate policy `id` as `caller` when it still holds the version `expected` and no
/// route references it, or replays the deletion that `key` already committed; REST and GraphQL
/// share it.
///
/// It returns the receipt of the change, because a command returns no data and a deleted rate
/// policy can no longer be read.
///
/// # Errors
///
/// The problem of a refused request: 404 for an unknown or deleted rate policy, 409 for a rate
/// policy that a route references or a concurrent change, 412 for a stale version, 422 for a key
/// reused for another request, 428 without a version, 500 for a storage failure.
pub(crate) async fn delete_rate_policy(
    state: &IamState,
    caller: &Principal,
    id: RatePolicyId,
    headers: VersionedWriteHeaders,
) -> Result<ChangeReceipt, Problem> {
    let VersionedWriteHeaders { expected, key } = headers;
    let actor = caller.actor();
    let form = delete_rate_policy_canonical_form(id, expected);
    let idempotency = key.map(|key| IdempotencyRequest {
        key,
        request_digest: state.request_digester.digest(&form),
    });
    if let Some(replayed) = find_replay(state, &actor, idempotency.as_ref()).await? {
        return Ok(replayed);
    }
    let change_id = ChangeId::from_uuid(state.uuid_generator.generate());
    let command = DeleteRatePolicyCommand {
        change_id,
        rate_policy_id: id,
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

/// The rate policy with the identifier, none when it is unknown or deleted.
///
/// # Errors
///
/// The 500 problem of a storage failure.
pub(crate) async fn find_rate_policy(
    state: &IamState,
    id: RatePolicyId,
) -> Result<Option<RatePolicyParts>, Problem> {
    Ok(state.query_bus.ask(GetRatePolicyQuery { id }).await?)
}

/// One page of rate policies for validated parameters.
///
/// # Errors
///
/// The 422 problem of an invalid cursor, the 500 problem of a storage failure.
pub(crate) async fn list_rate_policies(
    state: &IamState,
    params: ListRatePoliciesParams,
) -> Result<RatePolicyPage, Problem> {
    Ok(state.query_bus.ask(params.into_query()?).await?)
}

/// Creates a rate policy.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 409 for a duplicate name, 422 for invalid
/// fields or a reused idempotency key, 500 when the storage fails.
#[utoipa::path(
    post,
    path = "/rate-policies",
    operation_id = "api_rate_policies_post",
    tag = "iam",
    summary = "Creates a rate policy.",
    description = "Creates a rate policy at version 1, takes the next policy version and records `iam.rate_policy.created`. The period `periodMs` is a multiple of 1,000. A repeated `Idempotency-Key` with the same body within 24 hours returns the original result.",
    security(("bearerAuth" = [])),
    params(("Idempotency-Key" = Option<String>, Header, description = "Makes the creation safe to repeat for 24 hours; 1 to 255 visible ASCII characters."),
        ("Prefer" = Option<String>, Header, description = "What the write waits for: `wait=published` (the default) returns once Kafka acknowledged the policy version, `wait=propagated` is refused with 422 until the gateway pods report their versions.")),
    request_body(content = CreateRatePolicyRequest, content_type = "application/json"),
    responses(
        (
            status = 201,
            description = "The rate policy was created.",
            body = RatePolicyResponse,
            headers(
                ("location" = String, description = "Path of the created rate policy."),
                ("etag" = String, description = "The version of the rate policy in double quotes."),
                ("iam-policy-version" = String, description = "The policy version that the change produced."),
                ("iam-policy-offset" = String, description = "The offset at which Kafka stored the `__head` record of the policy version.")
            )
        ),
        (
            status = 202,
            description = "The change is committed and its policy version was not acknowledged by Kafka within `PUBLISH_WAIT_TIMEOUT`; it may not be in force on the gateway yet.",
            body = RatePolicyResponse,
            headers(
                ("location" = String, description = "Path of the created rate policy."),
                ("etag" = String, description = "The version of the rate policy in double quotes."),
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
        (status = 409, description = "A rate policy with this name exists.", body = Problem, content_type = "application/problem+json"),
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
    ValidatedJson(body): ValidatedJson<CreateRatePolicyRequest>,
) -> Result<(StatusCode, WriteHeaders, Json<RatePolicyResponse>), Problem> {
    let (policy, receipt) = create_rate_policy(&state, &caller, key, body).await?;
    let headers = created_headers(&receipt, RATE_POLICIES_PATH);
    Ok((
        write_status(&receipt, StatusCode::CREATED),
        headers,
        Json(RatePolicyResponse::from(policy)),
    ))
}

/// Reads a rate policy.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 404 for an unknown rate policy, 422 for an id
/// that is not a UUID.
#[utoipa::path(
    get,
    path = "/rate-policies/{id}",
    operation_id = "api_rate_policies_id_get",
    tag = "iam",
    summary = "Retrieves a rate policy.",
    description = "Returns the rate policy with the identifier, with its `ETag`.",
    security(("bearerAuth" = [])),
    params(("id" = String, Path, format = Uuid, description = "Rate policy identifier")),
    responses(
        (
            status = 200,
            description = "The rate policy.",
            body = RatePolicyResponse,
            headers(("etag" = String, description = "The version of the rate policy in double quotes."))
        ),
        (status = 400, description = "Invalid identifier.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 404, description = "Rate policy not found.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn get_one(
    State(state): State<IamState>,
    CallerPrincipal(_caller): CallerPrincipal,
    ApiPath(id): ApiPath<String>,
) -> Result<([(HeaderName, String); 1], Json<RatePolicyResponse>), Problem> {
    let policy = find_rate_policy(&state, parse_rate_policy_id(&id)?)
        .await?
        .ok_or(IamError::NotFound)?;
    let tag = etag(policy.version);
    Ok(([(ETAG, tag)], Json(RatePolicyResponse::from(policy))))
}

/// Updates a rate policy.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 404 for an unknown rate policy, 409 for a
/// duplicate name, 412 for a stale `If-Match`, 422 for invalid fields or a reused idempotency key,
/// 428 without `If-Match`, 500 when the storage fails.
#[utoipa::path(
    patch,
    path = "/rate-policies/{id}",
    operation_id = "api_rate_policies_id_patch",
    tag = "iam",
    summary = "Updates a rate policy.",
    description = "Changes the members of the body that are present when `If-Match` holds the current `ETag`, increases the version, takes the next policy version and records `iam.rate_policy.updated`. A repeated `Idempotency-Key` with the same request within 24 hours returns the original result.",
    security(("bearerAuth" = [])),
    params(
        ("id" = String, Path, format = Uuid, description = "Rate policy identifier"),
        ("If-Match" = String, Header, description = "The `ETag` of the version the update changes, such as `\"3\"`."),
        ("Idempotency-Key" = Option<String>, Header, description = "Makes the update safe to repeat for 24 hours; 1 to 255 visible ASCII characters."),
        ("Prefer" = Option<String>, Header, description = "What the write waits for: `wait=published` (the default) returns once Kafka acknowledged the policy version, `wait=propagated` is refused with 422 until the gateway pods report their versions.")
    ),
    request_body(content = UpdateRatePolicyRequest, content_type = "application/json"),
    responses(
        (
            status = 200,
            description = "The rate policy was updated.",
            body = RatePolicyResponse,
            headers(
                ("etag" = String, description = "The new version of the rate policy in double quotes."),
                ("iam-policy-version" = String, description = "The policy version that the change produced."),
                ("iam-policy-offset" = String, description = "The offset at which Kafka stored the `__head` record of the policy version.")
            )
        ),
        (
            status = 202,
            description = "The change is committed and its policy version was not acknowledged by Kafka within `PUBLISH_WAIT_TIMEOUT`; it may not be in force on the gateway yet.",
            body = RatePolicyResponse,
            headers(
                ("etag" = String, description = "The new version of the rate policy in double quotes."),
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
        (status = 404, description = "Rate policy not found.", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "A rate policy with this name exists, or the rate policy changed concurrently.", body = Problem, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is not the current version.", body = Problem, content_type = "application/problem+json"),
        (status = 413, description = "Request body too large.", body = Problem, content_type = "application/problem+json"),
        (status = 415, description = "Unsupported media type.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed, or the idempotency key was used for another request.", body = Problem, content_type = "application/problem+json"),
        (status = 428, description = "`If-Match` is missing.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn update(
    State(state): State<IamState>,
    CallerPrincipal(caller): CallerPrincipal,
    ApiPath(id): ApiPath<String>,
    headers: VersionedWriteHeaders,
    ValidatedJson(body): ValidatedJson<UpdateRatePolicyRequest>,
) -> Result<(StatusCode, WriteHeaders, Json<RatePolicyResponse>), Problem> {
    let (policy, receipt) =
        update_rate_policy(&state, &caller, parse_rate_policy_id(&id)?, headers, body).await?;
    Ok((
        write_status(&receipt, StatusCode::OK),
        change_headers(&receipt),
        Json(RatePolicyResponse::from(policy)),
    ))
}

/// Deletes a rate policy.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 404 for an unknown rate policy, 409 while a
/// route references it or after a concurrent change, 412 for a stale `If-Match`, 422 for an id
/// that is not a UUID or a reused idempotency key, 428 without `If-Match`, 500 when the storage
/// fails.
#[utoipa::path(
    delete,
    path = "/rate-policies/{id}",
    operation_id = "api_rate_policies_id_delete",
    tag = "iam",
    summary = "Deletes a rate policy.",
    description = "Deletes a rate policy when `If-Match` holds the current `ETag` and no route references it: the rate policy leaves the listings at once, its state record becomes a tombstone, the next policy version is committed, and `iam.rate_policy.deleted` and the audit record are written. A rate policy that a route references is refused with 409. A repeated `Idempotency-Key` with the same request within 24 hours returns the original result.",
    security(("bearerAuth" = [])),
    params(
        ("id" = String, Path, format = Uuid, description = "Rate policy identifier"),
        ("If-Match" = String, Header, description = "The `ETag` of the version the deletion ends, such as `\"3\"`."),
        ("Idempotency-Key" = Option<String>, Header, description = "Makes the deletion safe to repeat for 24 hours; 1 to 255 visible ASCII characters."),
        ("Prefer" = Option<String>, Header, description = "What the write waits for: `wait=published` (the default) returns once Kafka acknowledged the policy version, `wait=propagated` is refused with 422 until the gateway pods report their versions.")
    ),
    responses(
        (
            status = 200,
            description = "The rate policy was deleted.",
            body = DeleteRatePolicyResponse,
            headers(
                ("etag" = String, description = "The final version of the rate policy in double quotes."),
                ("iam-policy-version" = String, description = "The policy version that the change produced."),
                ("iam-policy-offset" = String, description = "The offset at which Kafka stored the `__head` record of the policy version.")
            )
        ),
        (
            status = 202,
            description = "The change is committed and its policy version was not acknowledged by Kafka within `PUBLISH_WAIT_TIMEOUT`; it may not be in force on the gateway yet.",
            body = DeleteRatePolicyResponse,
            headers(
                ("etag" = String, description = "The final version of the rate policy in double quotes."),
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
        (status = 404, description = "Rate policy not found.", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "A route still references the rate policy, or the rate policy changed concurrently.", body = Problem, content_type = "application/problem+json"),
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
) -> Result<(StatusCode, WriteHeaders, Json<DeleteRatePolicyResponse>), Problem> {
    let receipt = delete_rate_policy(&state, &caller, parse_rate_policy_id(&id)?, headers).await?;
    Ok((
        write_status(&receipt, StatusCode::OK),
        change_headers(&receipt),
        Json(DeleteRatePolicyResponse::from(&receipt)),
    ))
}

/// Lists rate policies.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 422 for invalid parameters.
#[utoipa::path(
    get,
    path = "/rate-policies",
    operation_id = "api_rate_policies_get",
    tag = "iam",
    summary = "Retrieves the collection of rate policies.",
    description = "Returns one page of rate policies in a stable order, with the `nextCursor` of the next page.",
    security(("bearerAuth" = [])),
    params(ListRatePoliciesParams),
    responses(
        (status = 200, description = "One page of rate policies.", body = RatePolicyPageResponse),
        (status = 400, description = "Invalid query parameter.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 422, description = "Validation failed.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn list(
    State(state): State<IamState>,
    CallerPrincipal(_caller): CallerPrincipal,
    ValidatedQuery(params): ValidatedQuery<ListRatePoliciesParams>,
) -> Result<Json<RatePolicyPageResponse>, Problem> {
    Ok(Json(RatePolicyPageResponse::from(
        list_rate_policies(&state, params).await?,
    )))
}

#[cfg(test)]
mod tests;
