//! REST handlers of the IAM roles, and the use-case calls that the GraphQL resolvers share.
//!
//! A handler takes the IAM state and the problem-aware extractors only (`ApiPath`,
//! `ValidatedQuery`, `ValidatedJson`, the IAM extractors `CallerPrincipal` and
//! `IdempotencyKeyHeader`, `PreferWaitHeader`); the test of the `handler` module checks every handler against that
//! rule.

use axum::Json;
use axum::extract::State;
use axum::http::header::ETAG;
use axum::http::{HeaderName, StatusCode};
use iam_domain::{
    ActorRef, ChangeId, ChangeReceipt, IdempotencyKey, IdempotencyRequest, RoleId, RoleParts,
};
use shared_application::http::{ApiPath, Problem, ValidatedJson, ValidatedQuery, Violation};

use super::IamState;
use super::dto::{
    CreateRoleRequest, DeleteRoleResponse, ListRolesParams, RolePageResponse, RoleResponse,
    UpdateRoleRequest, delete_role_canonical_form,
};
use super::extract::{
    CallerPrincipal, IdempotencyKeyHeader, PreferWaitHeader, VersionedWriteHeaders,
};
use super::response::{WriteHeaders, change_headers, created_headers, etag, write_status};
use crate::command::create_role::CreateRoleCommand;
use crate::command::delete_role::DeleteRoleCommand;
use crate::command::update_role::UpdateRoleCommand;
use crate::error::IamError;
use crate::principal::Principal;
use crate::query::get_change_receipt::GetChangeReceiptQuery;
use crate::query::get_idempotent_replay::GetIdempotentReplayQuery;
use crate::query::get_role::GetRoleQuery;
use crate::query::list_roles::RolePage;

/// The path of the role collection, under which a created role has its `Location`.
const ROLES_PATH: &str = "/api/roles";

/// The role id of a path or an argument.
///
/// # Errors
///
/// [`IamError::Invalid`] with a violation of `id` when the text is not a UUID.
pub(crate) fn parse_role_id(text: &str) -> Result<RoleId, IamError> {
    RoleId::parse(text).map_err(|_error| {
        IamError::Invalid(vec![Violation {
            property_path: "id".to_owned(),
            message: "This value is not a valid UUID.".to_owned(),
            code: "uuid".to_owned(),
        }])
    })
}

/// Creates a role as `caller`, or replays the creation that `key` already committed; REST and
/// GraphQL share it.
///
/// The role and the receipt of the change are read back, because a command returns no data.
///
/// # Errors
///
/// The problem of a refused request: 422 for invalid fields or a key reused for another request,
/// 409 for a duplicate name, 500 for a storage failure.
pub(crate) async fn create_role(
    state: &IamState,
    caller: &Principal,
    key: Option<IdempotencyKey>,
    request: CreateRoleRequest,
) -> Result<(RoleParts, ChangeReceipt), Problem> {
    let actor = caller.actor();
    let idempotency = key.map(|key| IdempotencyRequest {
        key,
        request_digest: state.request_digester.digest(&request.canonical_form()),
    });
    if let Some(replayed) = find_replay(state, &actor, idempotency.as_ref()).await? {
        return read_created(state, replayed).await;
    }
    let change_id = ChangeId::from_uuid(state.uuid_generator.generate());
    let role_id = RoleId::from_uuid(state.uuid_generator.generate());
    let command = CreateRoleCommand {
        change_id,
        role_id,
        actor,
        name: request.name,
        description: request.description,
        idempotency,
    };
    state.command_bus.dispatch(command).await?;
    let receipt = state
        .query_bus
        .ask(GetChangeReceiptQuery { change_id })
        .await?;
    read_created(state, receipt).await
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

/// The role that the receipt of a creation names.
async fn read_created(
    state: &IamState,
    receipt: ChangeReceipt,
) -> Result<(RoleParts, ChangeReceipt), Problem> {
    let id = RoleId::parse(receipt.target().target_id()).map_err(IamError::from)?;
    let role = find_role(state, id).await?.ok_or(IamError::NotFound)?;
    Ok((role, receipt))
}

/// Updates the role `id` as `caller` when it still holds the version `expected`, or replays the
/// update that `key` already committed; REST and GraphQL share it.
///
/// The receipt of the change and the role are read back, because a command returns no data.
///
/// # Errors
///
/// The problem of a refused request: 403 for a system role, 404 for an unknown role, 409 for a
/// duplicate name or a concurrent change, 412 for a stale version, 422 for invalid fields or a
/// key reused for another request, 500 for a storage failure.
pub(crate) async fn update_role(
    state: &IamState,
    caller: &Principal,
    id: RoleId,
    headers: VersionedWriteHeaders,
    request: UpdateRoleRequest,
) -> Result<(RoleParts, ChangeReceipt), Problem> {
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
        let command = UpdateRoleCommand {
            change_id,
            role_id: id,
            actor,
            expected,
            name: request.name,
            description: request.description.0,
            idempotency,
        };
        state.command_bus.dispatch(command).await?;
        state
            .query_bus
            .ask(GetChangeReceiptQuery { change_id })
            .await?
    };
    let role = find_role(state, id).await?.ok_or(IamError::NotFound)?;
    Ok((role, receipt))
}

/// Deletes the role `id` as `caller` when it still holds the version `expected`, and revokes every
/// assignment of it, or replays the deletion that `key` already committed; REST and GraphQL share
/// it.
///
/// It returns the receipt of the change, which holds the number of revoked assignments, because a
/// command returns no data and a deleted role can no longer be read.
///
/// # Errors
///
/// The problem of a refused request: 403 for a system role, 404 for an unknown or deleted role,
/// 409 for a concurrent change or a role with more assignments than one transaction revokes, 412
/// for a stale version, 422 for a key reused for another request, 500 for a storage failure.
pub(crate) async fn delete_role(
    state: &IamState,
    caller: &Principal,
    id: RoleId,
    headers: VersionedWriteHeaders,
) -> Result<ChangeReceipt, Problem> {
    let VersionedWriteHeaders { expected, key } = headers;
    let actor = caller.actor();
    let idempotency = key.map(|key| IdempotencyRequest {
        key,
        request_digest: state
            .request_digester
            .digest(&delete_role_canonical_form(id, expected)),
    });
    if let Some(replayed) = find_replay(state, &actor, idempotency.as_ref()).await? {
        return Ok(replayed);
    }
    let change_id = ChangeId::from_uuid(state.uuid_generator.generate());
    let command = DeleteRoleCommand {
        change_id,
        role_id: id,
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

/// The role with the identifier, none when it is unknown or deleted.
///
/// # Errors
///
/// The 500 problem of a storage failure.
pub(crate) async fn find_role(state: &IamState, id: RoleId) -> Result<Option<RoleParts>, Problem> {
    Ok(state.query_bus.ask(GetRoleQuery { id }).await?)
}

/// One page of roles for validated parameters.
///
/// # Errors
///
/// The 422 problem of an invalid cursor or kind, the 500 problem of a storage failure.
pub(crate) async fn list_roles(
    state: &IamState,
    params: ListRolesParams,
) -> Result<RolePage, Problem> {
    Ok(state.query_bus.ask(params.into_query()?).await?)
}

/// Creates a role.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 409 for a duplicate name, 422 for invalid
/// fields or a reused idempotency key, 500 when the storage fails.
#[utoipa::path(
    post,
    path = "/roles",
    operation_id = "api_roles_post",
    tag = "iam",
    summary = "Creates a role.",
    description = "Creates a custom role without grants at version 1 and records `iam.role.created`. A repeated `Idempotency-Key` with the same body within 24 hours returns the original result.",
    security(("bearerAuth" = [])),
    params(("Idempotency-Key" = Option<String>, Header, description = "Makes the creation safe to repeat for 24 hours; 1 to 255 visible ASCII characters."),
        ("Prefer" = Option<String>, Header, description = "What the write waits for: `wait=published` (the default) returns once Kafka acknowledged the policy version, `wait=propagated` is refused with 422 until the gateway pods report their versions.")),
    request_body(content = CreateRoleRequest, content_type = "application/json"),
    responses(
        (
            status = 201,
            description = "The role was created.",
            body = RoleResponse,
            headers(
                ("location" = String, description = "Path of the created role."),
                ("etag" = String, description = "The version of the role in double quotes.")
            )
        ),
        (
            status = 202,
            description = "The change is committed and its policy version was not acknowledged by Kafka within `PUBLISH_WAIT_TIMEOUT`; it may not be in force on the gateway yet.",
            body = RoleResponse,
            headers(
                ("location" = String, description = "Path of the created role."),
                ("etag" = String, description = "The version of the role in double quotes."),
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
        (status = 409, description = "A role with this name exists.", body = Problem, content_type = "application/problem+json"),
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
    ValidatedJson(body): ValidatedJson<CreateRoleRequest>,
) -> Result<(StatusCode, WriteHeaders, Json<RoleResponse>), Problem> {
    let (role, receipt) = create_role(&state, &caller, key, body).await?;
    let headers = created_headers(&receipt, ROLES_PATH);
    Ok((
        write_status(&receipt, StatusCode::CREATED),
        headers,
        Json(RoleResponse::from(role)),
    ))
}

/// Reads a role.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 404 for an unknown role, 422 for an id that is
/// not a UUID.
#[utoipa::path(
    get,
    path = "/roles/{id}",
    operation_id = "api_roles_id_get",
    tag = "iam",
    summary = "Retrieves a role.",
    description = "Returns the role with the identifier, with its `ETag`.",
    security(("bearerAuth" = [])),
    params(("id" = String, Path, format = Uuid, description = "Role identifier")),
    responses(
        (
            status = 200,
            description = "The role.",
            body = RoleResponse,
            headers(("etag" = String, description = "The version of the role in double quotes."))
        ),
        (status = 400, description = "Invalid identifier.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 404, description = "Role not found.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn get_one(
    State(state): State<IamState>,
    CallerPrincipal(_caller): CallerPrincipal,
    ApiPath(id): ApiPath<String>,
) -> Result<([(HeaderName, String); 1], Json<RoleResponse>), Problem> {
    let role = find_role(&state, parse_role_id(&id)?)
        .await?
        .ok_or(IamError::NotFound)?;
    let tag = etag(role.version);
    Ok(([(ETAG, tag)], Json(RoleResponse::from(role))))
}

/// Updates a role.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 for a system role, 404 for an unknown role,
/// 409 for a duplicate name, 412 for a stale `If-Match`, 422 for invalid fields or a reused
/// idempotency key, 428 without `If-Match`, 500 when the storage fails.
#[utoipa::path(
    patch,
    path = "/roles/{id}",
    operation_id = "api_roles_id_patch",
    tag = "iam",
    summary = "Updates a role.",
    description = "Renames a custom role or changes its description when `If-Match` holds the current `ETag`, increases the version and records `iam.role.updated`. A system role cannot be changed. A repeated `Idempotency-Key` with the same request within 24 hours returns the original result.",
    security(("bearerAuth" = [])),
    params(
        ("id" = String, Path, format = Uuid, description = "Role identifier"),
        ("If-Match" = String, Header, description = "The `ETag` of the version the update changes, such as `\"3\"`."),
        ("Idempotency-Key" = Option<String>, Header, description = "Makes the update safe to repeat for 24 hours; 1 to 255 visible ASCII characters."),
        ("Prefer" = Option<String>, Header, description = "What the write waits for: `wait=published` (the default) returns once Kafka acknowledged the policy version, `wait=propagated` is refused with 422 until the gateway pods report their versions.")
    ),
    request_body(content = UpdateRoleRequest, content_type = "application/json"),
    responses(
        (
            status = 200,
            description = "The role was updated.",
            body = RoleResponse,
            headers(("etag" = String, description = "The new version of the role in double quotes."))
        ),
        (
            status = 202,
            description = "The change is committed and its policy version was not acknowledged by Kafka within `PUBLISH_WAIT_TIMEOUT`; it may not be in force on the gateway yet.",
            body = RoleResponse,
            headers(
                ("etag" = String, description = "The new version of the role in double quotes."),
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
        (status = 403, description = "A system role cannot be changed.", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Role not found.", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "A role with this name exists.", body = Problem, content_type = "application/problem+json"),
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
    ValidatedJson(body): ValidatedJson<UpdateRoleRequest>,
) -> Result<(StatusCode, WriteHeaders, Json<RoleResponse>), Problem> {
    let (role, receipt) = update_role(&state, &caller, parse_role_id(&id)?, headers, body).await?;
    Ok((
        write_status(&receipt, StatusCode::OK),
        change_headers(&receipt),
        Json(RoleResponse::from(role)),
    ))
}

/// Deletes a role.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 for a system role, 404 for an unknown role,
/// 409 for a concurrent change or too many assignments, 412 for a stale `If-Match`, 422 for an id
/// that is not a UUID or a reused idempotency key, 428 without `If-Match`, 500 when the storage
/// fails.
#[utoipa::path(
    delete,
    path = "/roles/{id}",
    operation_id = "api_roles_id_delete",
    tag = "iam",
    summary = "Deletes a role.",
    description = "Deletes a custom role when `If-Match` holds the current `ETag` and revokes every assignment of it in the same transaction: the role and its assignments leave the active listings at once, the next policy version is committed, and `iam.role.deleted`, one `iam.user_role.revoked` per revoked assignment and the audit records are written. The response reports the number of revoked assignments. A system role cannot be deleted. A repeated `Idempotency-Key` with the same request within 24 hours returns the original result, including the number of revoked assignments.",
    security(("bearerAuth" = [])),
    params(
        ("id" = String, Path, format = Uuid, description = "Role identifier"),
        ("If-Match" = String, Header, description = "The `ETag` of the version the deletion ends, such as `\"3\"`."),
        ("Idempotency-Key" = Option<String>, Header, description = "Makes the deletion safe to repeat for 24 hours; 1 to 255 visible ASCII characters."),
        ("Prefer" = Option<String>, Header, description = "What the write waits for: `wait=published` (the default) returns once Kafka acknowledged the policy version, `wait=propagated` is refused with 422 until the gateway pods report their versions.")
    ),
    responses(
        (
            status = 200,
            description = "The role was deleted and its assignments were revoked.",
            body = DeleteRoleResponse,
            headers(
                ("etag" = String, description = "The final version of the role in double quotes."),
                ("iam-policy-version" = String, description = "The policy version that the change produced."),
                ("iam-policy-offset" = String, description = "The offset at which Kafka stored the `__head` record of the policy version; present when the change affected decisions and was acknowledged.")
            )
        ),
        (
            status = 202,
            description = "The change is committed and its policy version was not acknowledged by Kafka within `PUBLISH_WAIT_TIMEOUT`; it may not be in force on the gateway yet.",
            body = DeleteRoleResponse,
            headers(
                ("etag" = String, description = "The final version of the role in double quotes."),
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
        (status = 403, description = "A system role cannot be deleted.", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Role not found.", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The role or one of its assignments changed concurrently, or the role has more assignments than one transaction revokes.", body = Problem, content_type = "application/problem+json"),
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
) -> Result<(StatusCode, WriteHeaders, Json<DeleteRoleResponse>), Problem> {
    let receipt = delete_role(&state, &caller, parse_role_id(&id)?, headers).await?;
    Ok((
        write_status(&receipt, StatusCode::OK),
        change_headers(&receipt),
        Json(DeleteRoleResponse::from(&receipt)),
    ))
}

/// Lists roles.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 422 for invalid parameters.
#[utoipa::path(
    get,
    path = "/roles",
    operation_id = "api_roles_get",
    tag = "iam",
    summary = "Retrieves the collection of roles.",
    description = "Returns one page of roles in a stable order, with the `nextCursor` of the next page. Filters: `namePrefix` (without regard to case) and `kind`.",
    security(("bearerAuth" = [])),
    params(ListRolesParams),
    responses(
        (status = 200, description = "One page of roles.", body = RolePageResponse),
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
    ValidatedQuery(params): ValidatedQuery<ListRolesParams>,
) -> Result<Json<RolePageResponse>, Problem> {
    Ok(Json(RolePageResponse::from(
        list_roles(&state, params).await?,
    )))
}

#[cfg(test)]
mod tests;
