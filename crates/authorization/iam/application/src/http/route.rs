//! REST handlers of the routes of the gateway configuration, and the use-case calls that the
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
    ActorRef, ChangeId, ChangeReceipt, IdempotencyKey, IdempotencyRequest, RouteDraft, RouteId,
    RouteParts,
};
use shared_application::http::{ApiPath, Problem, ValidatedJson, ValidatedQuery, Violation};

use super::IamState;
use super::extract::{
    CallerPrincipal, IdempotencyKeyHeader, PreferWaitHeader, VersionedWriteHeaders,
};
use super::response::{WriteHeaders, change_headers, created_headers, etag, write_status};
use super::user_role::find_replay;
use crate::command::create_route::CreateRouteCommand;
use crate::command::delete_route::DeleteRouteCommand;
use crate::command::update_route::UpdateRouteCommand;
use crate::error::IamError;
use crate::principal::Principal;
use crate::query::get_change_receipt::GetChangeReceiptQuery;
use crate::query::get_route::GetRouteQuery;
use crate::query::list_routes::RoutePage;
use dto::{
    CreateRouteRequest, ListRoutesParams, RoutePageResponse, RouteResponse, UpdateRouteRequest,
    delete_route_canonical_form,
};

/// The path of the route collection, under which a created route has its `Location`.
const ROUTES_PATH: &str = "/api/routes";

/// The route id of a path or an argument.
///
/// # Errors
///
/// [`IamError::Invalid`] with a violation of `id` when the text is not a UUID.
pub(crate) fn parse_route_id(text: &str) -> Result<RouteId, IamError> {
    RouteId::parse(text).map_err(|_error| {
        IamError::Invalid(vec![Violation {
            property_path: "id".to_owned(),
            message: "This value is not a valid UUID.".to_owned(),
            code: "uuid".to_owned(),
        }])
    })
}

/// Creates a route as `caller`, or replays the creation that `key` already committed; REST and
/// GraphQL share it.
///
/// The route and the receipt of the change are read back, because a command returns no data.
///
/// # Errors
///
/// The problem of a refused request: 403 for a caller without the route key of the service or
/// without `iam:route:anonymous` where the route needs it, 409 for a route that conflicts with
/// another route of its host or belongs to the `iam` service, 422 for invalid fields, an unknown
/// upstream or rate policy, a service that differs from the upstream's or a key reused for another
/// request, 500 for a storage failure.
pub(crate) async fn create_route(
    state: &IamState,
    caller: &Principal,
    key: Option<IdempotencyKey>,
    request: CreateRouteRequest,
) -> Result<(RouteParts, ChangeReceipt), Problem> {
    let actor = caller.actor();
    let idempotency = key.map(|key| IdempotencyRequest {
        key,
        request_digest: state.request_digester.digest(&request.canonical_form()),
    });
    if let Some(replayed) = find_replay(state, &actor, idempotency.as_ref()).await? {
        return read_created(state, replayed).await;
    }
    let draft = request.into_draft()?;
    let change_id = ChangeId::from_uuid(state.uuid_generator.generate());
    let route_id = RouteId::from_uuid(state.uuid_generator.generate());
    let command = create_command(change_id, route_id, actor, idempotency, draft);
    state.command_bus.dispatch(command).await?;
    let receipt = state
        .query_bus
        .ask(GetChangeReceiptQuery { change_id })
        .await?;
    read_created(state, receipt).await
}

/// The command that creates the route of the request.
const fn create_command(
    change_id: ChangeId,
    route_id: RouteId,
    actor: ActorRef,
    idempotency: Option<IdempotencyRequest>,
    draft: RouteDraft,
) -> CreateRouteCommand {
    CreateRouteCommand {
        change_id,
        route_id,
        actor,
        draft,
        idempotency,
    }
}

/// The route that the receipt of a creation names.
async fn read_created(
    state: &IamState,
    receipt: ChangeReceipt,
) -> Result<(RouteParts, ChangeReceipt), Problem> {
    let id = RouteId::parse(receipt.target().target_id()).map_err(IamError::from)?;
    let route = find_route(state, id).await?.ok_or(IamError::NotFound)?;
    Ok((route, receipt))
}

/// Updates the route `id` as `caller` when it still holds the version `expected`, or replays the
/// update that `key` already committed; REST and GraphQL share it.
///
/// The receipt of the change and the route are read back, because a command returns no data.
///
/// # Errors
///
/// The problem of a refused request: 403 for a caller without the route key or the anonymous key,
/// 404 for an unknown route, 409 for a conflict, a concurrent change or a route that IAM manages
/// itself, 412 for a stale version, 422 for invalid fields or a key reused for another request,
/// 428 without a version, 500 for a storage failure.
pub(crate) async fn update_route(
    state: &IamState,
    caller: &Principal,
    id: RouteId,
    headers: VersionedWriteHeaders,
    request: UpdateRouteRequest,
) -> Result<(RouteParts, ChangeReceipt), Problem> {
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
        let command = UpdateRouteCommand {
            change_id,
            route_id: id,
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
    let route = find_route(state, id).await?.ok_or(IamError::NotFound)?;
    Ok((route, receipt))
}

/// Deletes the route `id` as `caller` when it still holds the version `expected`, or replays the
/// deletion that `key` already committed; REST and GraphQL share it.
///
/// It returns the receipt of the change, because a command returns no data and a deleted route can
/// no longer be read.
///
/// # Errors
///
/// The problem of a refused request: 403 for a caller without the route key, 404 for an unknown or
/// deleted route, 409 for a concurrent change or a route that IAM manages itself, 412 for a stale
/// version, 422 for a key reused for another request, 428 without a version, 500 for a storage
/// failure.
pub(crate) async fn delete_route(
    state: &IamState,
    caller: &Principal,
    id: RouteId,
    headers: VersionedWriteHeaders,
) -> Result<ChangeReceipt, Problem> {
    let VersionedWriteHeaders { expected, key } = headers;
    let actor = caller.actor();
    let idempotency = key.map(|key| IdempotencyRequest {
        key,
        request_digest: state
            .request_digester
            .digest(&delete_route_canonical_form(id, expected)),
    });
    if let Some(replayed) = find_replay(state, &actor, idempotency.as_ref()).await? {
        return Ok(replayed);
    }
    let change_id = ChangeId::from_uuid(state.uuid_generator.generate());
    let command = DeleteRouteCommand {
        change_id,
        route_id: id,
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

/// The route with the identifier, none when it is unknown or deleted.
///
/// # Errors
///
/// The 500 problem of a storage failure.
pub(crate) async fn find_route(
    state: &IamState,
    id: RouteId,
) -> Result<Option<RouteParts>, Problem> {
    Ok(state.query_bus.ask(GetRouteQuery { id }).await?)
}

/// One page of routes for validated parameters.
///
/// # Errors
///
/// The 422 problem of an invalid cursor or filter, the 500 problem of a storage failure.
pub(crate) async fn list_routes(
    state: &IamState,
    params: ListRoutesParams,
) -> Result<RoutePage, Problem> {
    Ok(state.query_bus.ask(params.into_query()?).await?)
}

/// Creates a route.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without the route key of the service or
/// without `iam:route:anonymous` for an anonymous or audit-only route, 409 for a conflicting
/// route or a route of the `iam` service, 422 for invalid fields or a reused idempotency key, 500
/// when the storage fails.
#[utoipa::path(
    post,
    path = "/routes",
    operation_id = "api_routes_post",
    tag = "iam",
    summary = "Creates a route.",
    description = "Registers a route of one host, a set of methods and a path pattern that the gateway forwards to an upstream, at version 1, writes its `route/<id>` state record, takes the next policy version and records `iam.route.created`. The caller needs `iam:route:{service}` or `iam:route:*`, and `iam:route:anonymous` to make the route anonymous or audit-only. The route `service` must equal the `catalogService` of its upstream. A route that overlaps another route of its host, or whose candidate route table the gateway could not build, is refused with 409 `route-table-conflict`; a route of the `iam` service with 409 `system-entry`. A repeated `Idempotency-Key` with the same body within 24 hours returns the original result.",
    security(("bearerAuth" = [])),
    params(("Idempotency-Key" = Option<String>, Header, description = "Makes the creation safe to repeat for 24 hours; 1 to 255 visible ASCII characters."),
        ("Prefer" = Option<String>, Header, description = "What the write waits for: `wait=published` (the default) returns once Kafka acknowledged the policy version, `wait=propagated` is refused with 422 until the gateway pods report their versions.")),
    request_body(content = CreateRouteRequest, content_type = "application/json"),
    responses(
        (
            status = 201,
            description = "The route was created.",
            body = RouteResponse,
            headers(
                ("location" = String, description = "Path of the created route."),
                ("etag" = String, description = "The version of the route in double quotes."),
                ("iam-policy-version" = String, description = "The policy version that the change produced."),
                ("iam-policy-offset" = String, description = "The offset at which Kafka stored the `__head` record of the policy version; present when the change was acknowledged.")
            )
        ),
        (
            status = 202,
            description = "The change is committed and its policy version was not acknowledged by Kafka within `PUBLISH_WAIT_TIMEOUT`; it may not be in force on the gateway yet.",
            body = RouteResponse,
            headers(
                ("location" = String, description = "Path of the created route."),
                ("etag" = String, description = "The version of the route in double quotes."),
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
        (status = 403, description = "The caller lacks the operation key, the route key of the service or `iam:route:anonymous`.", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The route conflicts with another route of its host, or it belongs to the `iam` service.", body = Problem, content_type = "application/problem+json"),
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
    ValidatedJson(body): ValidatedJson<CreateRouteRequest>,
) -> Result<(StatusCode, WriteHeaders, Json<RouteResponse>), Problem> {
    let (route, receipt) = create_route(&state, &caller, key, body).await?;
    let headers = created_headers(&receipt, ROUTES_PATH);
    Ok((
        write_status(&receipt, StatusCode::CREATED),
        headers,
        Json(RouteResponse::from(route)),
    ))
}

/// Reads a route.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without the operation key, 404 for an
/// unknown route, 422 for an id that is not a UUID.
#[utoipa::path(
    get,
    path = "/routes/{id}",
    operation_id = "api_routes_id_get",
    tag = "iam",
    summary = "Retrieves a route.",
    description = "Returns the route with the identifier, with its `ETag`.",
    security(("bearerAuth" = [])),
    params(("id" = String, Path, format = Uuid, description = "Route identifier")),
    responses(
        (
            status = 200,
            description = "The route.",
            body = RouteResponse,
            headers(("etag" = String, description = "The version of the route in double quotes."))
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
        (status = 404, description = "Route not found.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn get_one(
    State(state): State<IamState>,
    CallerPrincipal(_caller): CallerPrincipal,
    ApiPath(id): ApiPath<String>,
) -> Result<([(HeaderName, String); 1], Json<RouteResponse>), Problem> {
    let route = find_route(&state, parse_route_id(&id)?)
        .await?
        .ok_or(IamError::NotFound)?;
    let tag = etag(route.version);
    Ok(([(ETAG, tag)], Json(RouteResponse::from(route))))
}

/// Updates a route.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without the route key of the service or
/// without `iam:route:anonymous` for a change of `anonymous` or `enforcement`, 404 for an unknown
/// route, 409 for a conflict or a system route, 412 for a stale `If-Match`, 422 for invalid fields
/// or a reused idempotency key, 428 without `If-Match`, 500 when the storage fails.
#[utoipa::path(
    patch,
    path = "/routes/{id}",
    operation_id = "api_routes_id_patch",
    tag = "iam",
    summary = "Updates a route.",
    description = "Changes the members named in the body when `If-Match` holds the current `ETag`, increases the version, writes the `route/<id>` state record, takes the next policy version and records `iam.route.updated`. The caller needs `iam:route:{service}` or `iam:route:*` for the service before and after the change, and `iam:route:anonymous` to change `anonymous` or `enforcement`, which is audited with the old and the new value. A system route and one of the `iam` service are refused with 409 `system-entry`. A repeated `Idempotency-Key` with the same request within 24 hours returns the original result.",
    security(("bearerAuth" = [])),
    params(
        ("id" = String, Path, format = Uuid, description = "Route identifier"),
        ("If-Match" = String, Header, description = "The `ETag` of the version the update changes, such as `\"3\"`."),
        ("Idempotency-Key" = Option<String>, Header, description = "Makes the update safe to repeat for 24 hours; 1 to 255 visible ASCII characters."),
        ("Prefer" = Option<String>, Header, description = "What the write waits for: `wait=published` (the default) returns once Kafka acknowledged the policy version, `wait=propagated` is refused with 422 until the gateway pods report their versions.")
    ),
    request_body(content = UpdateRouteRequest, content_type = "application/json"),
    responses(
        (
            status = 200,
            description = "The route was updated.",
            body = RouteResponse,
            headers(
                ("etag" = String, description = "The new version of the route in double quotes."),
                ("iam-policy-version" = String, description = "The policy version that the change produced."),
                ("iam-policy-offset" = String, description = "The offset at which Kafka stored the `__head` record of the policy version; present when the change was acknowledged.")
            )
        ),
        (
            status = 202,
            description = "The change is committed and its policy version was not acknowledged by Kafka within `PUBLISH_WAIT_TIMEOUT`; it may not be in force on the gateway yet.",
            body = RouteResponse,
            headers(
                ("etag" = String, description = "The new version of the route in double quotes."),
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
        (status = 403, description = "The caller lacks the operation key, the route key of the service or `iam:route:anonymous`.", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Route not found.", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The route is a system route or belongs to the `iam` service, it conflicts with another route of its host, or it changed concurrently.", body = Problem, content_type = "application/problem+json"),
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
    ValidatedJson(body): ValidatedJson<UpdateRouteRequest>,
) -> Result<(StatusCode, WriteHeaders, Json<RouteResponse>), Problem> {
    let (route, receipt) =
        update_route(&state, &caller, parse_route_id(&id)?, headers, body).await?;
    Ok((
        write_status(&receipt, StatusCode::OK),
        change_headers(&receipt),
        Json(RouteResponse::from(route)),
    ))
}

/// Deletes a route.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without the route key of the service, 404
/// for an unknown route, 409 for a system route, 412 for a stale `If-Match`, 422 for an id that
/// is not a UUID or a reused idempotency key, 428 without `If-Match`, 500 when the storage fails.
#[utoipa::path(
    delete,
    path = "/routes/{id}",
    operation_id = "api_routes_id_delete",
    tag = "iam",
    summary = "Deletes a route.",
    description = "Deletes the route when `If-Match` holds the current `ETag`: it leaves the listings at once, its `route/<id>` state record becomes a tombstone, the next policy version is committed, and `iam.route.deleted` and an audit record are written in the same transaction. The caller needs `iam:route:{service}` or `iam:route:*`; a system route and one of the `iam` service are refused with 409 `system-entry`. A repeated `Idempotency-Key` with the same request within 24 hours returns the original result.",
    security(("bearerAuth" = [])),
    params(
        ("id" = String, Path, format = Uuid, description = "Route identifier"),
        ("If-Match" = String, Header, description = "The `ETag` of the version the deletion ends, such as `\"3\"`."),
        ("Idempotency-Key" = Option<String>, Header, description = "Makes the deletion safe to repeat for 24 hours; 1 to 255 visible ASCII characters."),
        ("Prefer" = Option<String>, Header, description = "What the write waits for: `wait=published` (the default) returns once Kafka acknowledged the policy version, `wait=propagated` is refused with 422 until the gateway pods report their versions.")
    ),
    responses(
        (
            status = 204,
            description = "The route was deleted.",
            headers(
                ("etag" = String, description = "The final version of the route in double quotes."),
                ("iam-policy-version" = String, description = "The policy version that the change produced."),
                ("iam-policy-offset" = String, description = "The offset at which Kafka stored the `__head` record of the policy version; present when the change was acknowledged.")
            )
        ),
        (
            status = 202,
            description = "The change is committed and its policy version was not acknowledged by Kafka within `PUBLISH_WAIT_TIMEOUT`; it may not be in force on the gateway yet.",
            headers(
                ("etag" = String, description = "The final version of the route in double quotes."),
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
        (status = 403, description = "The caller lacks the operation key or the route key of the service.", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Route not found.", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The route is a system route or belongs to the `iam` service, or it changed concurrently.", body = Problem, content_type = "application/problem+json"),
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
    let receipt = delete_route(&state, &caller, parse_route_id(&id)?, headers).await?;
    Ok((
        write_status(&receipt, StatusCode::NO_CONTENT),
        change_headers(&receipt),
    ))
}

/// Lists routes.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without the operation key, 422 for invalid
/// parameters.
#[utoipa::path(
    get,
    path = "/routes",
    operation_id = "api_routes_get",
    tag = "iam",
    summary = "Retrieves the collection of routes.",
    description = "Returns one page of the routes that are not deleted in a stable order, with the `nextCursor` of the next page. The filters `host`, `upstream` and `service` keep the routes that match every filter given.",
    security(("bearerAuth" = [])),
    params(ListRoutesParams),
    responses(
        (status = 200, description = "One page of routes.", body = RoutePageResponse),
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
    ValidatedQuery(params): ValidatedQuery<ListRoutesParams>,
) -> Result<Json<RoutePageResponse>, Problem> {
    Ok(Json(RoutePageResponse::from(
        list_routes(&state, params).await?,
    )))
}

#[cfg(test)]
mod tests;
