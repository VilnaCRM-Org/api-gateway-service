//! REST handlers of the IAM role assignments, and the use-case calls that the GraphQL resolvers
//! share.
//!
//! A handler takes the IAM state and the problem-aware extractors only (`ApiPath`,
//! `ValidatedQuery`, `ValidatedJson`, the IAM extractors `CallerPrincipal` and
//! `IdempotencyKeyHeader`); the test of the `handler` module checks every handler against that
//! rule.

pub mod dto;

use axum::Json;
use axum::extract::State;
use axum::http::header::ETAG;
use axum::http::{HeaderName, StatusCode};
use iam_domain::{
    ActorRef, ChangeId, ChangeReceipt, IdempotencyKey, IdempotencyRequest, UserRoleId,
};
use shared_application::http::{ApiPath, Problem, ValidatedJson, ValidatedQuery, Violation};

use super::IamState;
use super::extract::{CallerPrincipal, IdempotencyKeyHeader};
use super::response::{WriteHeaders, created_headers, etag};
use crate::command::assign_user_role::AssignUserRoleCommand;
use crate::error::IamError;
use crate::principal::Principal;
use crate::query::get_change_receipt::GetChangeReceiptQuery;
use crate::query::get_idempotent_replay::GetIdempotentReplayQuery;
use crate::query::get_user_role::{GetUserRoleQuery, UserRoleView};
use crate::query::list_user_roles::UserRolePage;
use dto::{AssignUserRoleRequest, ListUserRolesParams, UserRolePageResponse, UserRoleResponse};

/// The path of the assignment collection, under which a created assignment has its `Location`.
const USER_ROLES_PATH: &str = "/api/user-roles";

/// The assignment id of a path or an argument.
///
/// # Errors
///
/// [`IamError::Invalid`] with a violation of `id` when the text is not a UUID.
pub(crate) fn parse_user_role_id(text: &str) -> Result<UserRoleId, IamError> {
    UserRoleId::parse(text).map_err(|_error| {
        IamError::Invalid(vec![Violation {
            property_path: "id".to_owned(),
            message: "This value is not a valid UUID.".to_owned(),
            code: "uuid".to_owned(),
        }])
    })
}

/// Assigns a role as `caller`, or replays the assignment that `key` already committed; REST and
/// GraphQL share it.
///
/// The assignment and the receipt of the change are read back, because a command returns no data.
///
/// # Errors
///
/// The problem of a refused request: 422 for invalid values, an unknown role, a past expiry or a
/// key reused for another request, 409 for a duplicate assignment, 500 for a storage failure.
pub(crate) async fn assign_user_role(
    state: &IamState,
    caller: &Principal,
    key: Option<IdempotencyKey>,
    request: AssignUserRoleRequest,
) -> Result<(UserRoleView, ChangeReceipt), Problem> {
    let parsed = request.parse()?;
    let actor = caller.actor();
    let idempotency = key.map(|key| IdempotencyRequest {
        key,
        request_digest: state.request_digester.digest(&request.canonical_form()),
    });
    if let Some(replayed) = find_replay(state, &actor, idempotency.as_ref()).await? {
        return read_assigned(state, replayed).await;
    }
    let change_id = ChangeId::from_uuid(state.uuid_generator.generate());
    let user_role_id = UserRoleId::from_uuid(state.uuid_generator.generate());
    let command = AssignUserRoleCommand {
        change_id,
        user_role_id,
        actor,
        subject: parsed.subject,
        role_id: parsed.role_id,
        scope: parsed.scope,
        expires_at: parsed.expires_at,
        idempotency,
    };
    state.command_bus.dispatch(command).await?;
    let receipt = state
        .query_bus
        .ask(GetChangeReceiptQuery { change_id })
        .await?;
    read_assigned(state, receipt).await
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

/// The assignment that the receipt of an assignment names.
async fn read_assigned(
    state: &IamState,
    receipt: ChangeReceipt,
) -> Result<(UserRoleView, ChangeReceipt), Problem> {
    let id = UserRoleId::parse(receipt.target().target_id()).map_err(IamError::from)?;
    let user_role = find_user_role(state, id).await?.ok_or(IamError::NotFound)?;
    Ok((user_role, receipt))
}

/// The assignment with the identifier and its role name, none when it is unknown or revoked.
///
/// # Errors
///
/// The 500 problem of a storage failure.
pub(crate) async fn find_user_role(
    state: &IamState,
    id: UserRoleId,
) -> Result<Option<UserRoleView>, Problem> {
    Ok(state.query_bus.ask(GetUserRoleQuery { id }).await?)
}

/// One page of assignments for validated parameters.
///
/// # Errors
///
/// The 422 problem of an invalid cursor, kind or identifier, the 500 problem of a storage failure.
pub(crate) async fn list_user_roles(
    state: &IamState,
    params: ListUserRolesParams,
) -> Result<UserRolePage, Problem> {
    Ok(state.query_bus.ask(params.into_query()?).await?)
}

/// Assigns a role.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 409 for a duplicate assignment, 422 for invalid
/// values, an unknown role, a past expiry or a reused idempotency key, 500 when the storage fails.
#[utoipa::path(
    post,
    path = "/user-roles",
    operation_id = "api_user_roles_post",
    tag = "iam",
    summary = "Assigns a role to a subject.",
    description = "Assigns an existing role to a user or a service principal at global or project scope, takes the next policy version and records `iam.user_role.assigned`, and `iam.privileged_role.assigned` as well when the role grants a wildcard or a reserved `iam:` key. The triple of subject, role and scope is unique among assignments that are not revoked. A repeated `Idempotency-Key` with the same body within 24 hours returns the original result.",
    security(("bearerAuth" = [])),
    params(("Idempotency-Key" = Option<String>, Header, description = "Makes the assignment safe to repeat for 24 hours; 1 to 255 visible ASCII characters.")),
    request_body(content = AssignUserRoleRequest, content_type = "application/json"),
    responses(
        (
            status = 201,
            description = "The role was assigned.",
            body = UserRoleResponse,
            headers(
                ("location" = String, description = "Path of the created assignment."),
                ("etag" = String, description = "The version of the assignment in double quotes."),
                ("iam-policy-version" = String, description = "The policy version that the change produced.")
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
        (status = 409, description = "The role is already assigned to the subject at this scope.", body = Problem, content_type = "application/problem+json"),
        (status = 413, description = "Request body too large.", body = Problem, content_type = "application/problem+json"),
        (status = 415, description = "Unsupported media type.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed: an invalid value, an unknown role (`roleId`), an expiry in the past (`expiresAt`), or the idempotency key was used for another request.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn assign(
    State(state): State<IamState>,
    CallerPrincipal(caller): CallerPrincipal,
    IdempotencyKeyHeader(key): IdempotencyKeyHeader,
    ValidatedJson(body): ValidatedJson<AssignUserRoleRequest>,
) -> Result<(StatusCode, WriteHeaders, Json<UserRoleResponse>), Problem> {
    let (user_role, receipt) = assign_user_role(&state, &caller, key, body).await?;
    let headers = created_headers(&receipt, USER_ROLES_PATH);
    Ok((
        StatusCode::CREATED,
        headers,
        Json(UserRoleResponse::from(user_role)),
    ))
}

/// Reads an assignment.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 404 for an unknown or revoked assignment, 422
/// for an id that is not a UUID.
#[utoipa::path(
    get,
    path = "/user-roles/{id}",
    operation_id = "api_user_roles_id_get",
    tag = "iam",
    summary = "Retrieves a role assignment.",
    description = "Returns the assignment with the identifier, with the name of its role and its `ETag`. An assignment that has expired is still returned; a revoked one is not.",
    security(("bearerAuth" = [])),
    params(("id" = String, Path, format = Uuid, description = "Assignment identifier")),
    responses(
        (
            status = 200,
            description = "The assignment.",
            body = UserRoleResponse,
            headers(("etag" = String, description = "The version of the assignment in double quotes."))
        ),
        (status = 400, description = "Invalid identifier.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 404, description = "Assignment not found.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn get_one(
    State(state): State<IamState>,
    CallerPrincipal(_caller): CallerPrincipal,
    ApiPath(id): ApiPath<String>,
) -> Result<([(HeaderName, String); 1], Json<UserRoleResponse>), Problem> {
    let user_role = find_user_role(&state, parse_user_role_id(&id)?)
        .await?
        .ok_or(IamError::NotFound)?;
    let tag = etag(user_role.user_role.version);
    Ok(([(ETAG, tag)], Json(UserRoleResponse::from(user_role))))
}

/// Lists assignments.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 422 for invalid parameters.
#[utoipa::path(
    get,
    path = "/user-roles",
    operation_id = "api_user_roles_get",
    tag = "iam",
    summary = "Retrieves the collection of role assignments.",
    description = "Returns one page of assignments that are not revoked in a stable order, with the `nextCursor` of the next page. Filters: `subjectKind`, `subjectId`, `roleId`, `projectId` and `includeExpired`, which lists assignments that have expired as well.",
    security(("bearerAuth" = [])),
    params(ListUserRolesParams),
    responses(
        (status = 200, description = "One page of assignments.", body = UserRolePageResponse),
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
    ValidatedQuery(params): ValidatedQuery<ListUserRolesParams>,
) -> Result<Json<UserRolePageResponse>, Problem> {
    Ok(Json(UserRolePageResponse::from(
        list_user_roles(&state, params).await?,
    )))
}

#[cfg(test)]
mod tests;
