//! REST handler of the effective permissions of a user, and the use-case call that the GraphQL
//! resolver shares.
//!
//! A handler takes the IAM state and the problem-aware extractors only (`ApiPath`,
//! `ValidatedQuery`, the IAM extractor `CallerPrincipal`); the test of the `handler` module checks
//! every handler against that rule.

pub mod dto;

use axum::Json;
use axum::extract::State;
use shared_application::http::{ApiPath, Problem, ValidatedQuery};

use super::IamState;
use super::extract::CallerPrincipal;
use crate::query::get_user_role_permissions::UserRolePermissionsView;
use dto::{UserRolePermissionsParams, UserRolePermissionsResponse};

/// The effective permissions of the user `user_id` for validated parameters.
///
/// # Errors
///
/// The 422 problem of a user id that is not a UUID, a project that is not a UUID or a service that
/// is not a service name, the 500 problem of a storage failure.
pub(crate) async fn find_user_role_permissions(
    state: &IamState,
    user_id: &str,
    params: UserRolePermissionsParams,
) -> Result<UserRolePermissionsView, Problem> {
    let query = params.into_query(user_id)?;
    Ok(state.query_bus.ask(query).await?)
}

/// Reads the effective permissions of a user.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without the catalogue key of the operation,
/// 422 for an id or a parameter that is invalid.
#[utoipa::path(
    get,
    path = "/users/{userId}/role-permissions",
    operation_id = "api_users_user_id_role_permissions_get",
    tag = "iam",
    summary = "Retrieves the effective permissions of a user.",
    description = "Returns every key and wildcard that the active assignments of the user hold, each with the roles that grant it, its scopes (`all` or the project ids), the shortest expiry among the contributing assignments that expire, and the `policyVersion` the answer was composed at. Assignments that have expired grant nothing, a reserved `iam:` key counts only through a global assignment, and a wildcard never covers a sensitive key, exactly as in a decision. `projectId` keeps the global assignments and those of the project; `service` keeps the keys and wildcards of the service. A user without assignments has an empty list.",
    security(("bearerAuth" = [])),
    params(
        ("userId" = String, Path, format = Uuid, description = "User identifier"),
        UserRolePermissionsParams
    ),
    responses(
        (status = 200, description = "The effective permissions of the user.", body = UserRolePermissionsResponse),
        (status = 400, description = "Invalid identifier or query parameter.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 403, description = "The caller does not hold the key of the operation.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn list(
    State(state): State<IamState>,
    CallerPrincipal(_caller): CallerPrincipal,
    ApiPath(user_id): ApiPath<String>,
    ValidatedQuery(params): ValidatedQuery<UserRolePermissionsParams>,
) -> Result<Json<UserRolePermissionsResponse>, Problem> {
    let view = find_user_role_permissions(&state, &user_id, params).await?;
    Ok(Json(UserRolePermissionsResponse::from(&view)))
}

#[cfg(test)]
mod tests;
