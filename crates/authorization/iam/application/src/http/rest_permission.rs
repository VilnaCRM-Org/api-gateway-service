//! REST handlers that read the REST permission catalogue, and the use-case calls that the GraphQL
//! resolvers share.
//!
//! A handler takes the IAM state and the problem-aware extractors only (`ApiPath`,
//! `ValidatedQuery` and the IAM extractor `CallerPrincipal`); the test of the `handler` module
//! checks every handler against that rule.

pub mod dto;

use axum::Json;
use axum::extract::State;
use iam_domain::PermissionId;
use shared_application::http::{ApiPath, Problem, ValidatedQuery};

use super::IamState;
use super::extract::CallerPrincipal;
use super::graphql_permission::parse_permission_id;
use crate::error::IamError;
use crate::query::get_rest_permission::GetRestPermissionQuery;
use crate::query::get_rest_permissions::{RestPermissionPage, RestPermissionView};
use dto::{ListRestPermissionsParams, RestPermissionPageResponse, RestPermissionResponse};

/// One page of entries for validated parameters.
///
/// # Errors
///
/// The 422 problem of an invalid cursor, service or method, the 500 problem of a storage failure.
pub(crate) async fn list_rest_permissions(
    state: &IamState,
    params: ListRestPermissionsParams,
) -> Result<RestPermissionPage, Problem> {
    Ok(state.query_bus.ask(params.into_query()?).await?)
}

/// The entry with the identifier, with its versions and roles; none when it is unknown.
///
/// # Errors
///
/// The 500 problem of a storage failure.
pub(crate) async fn find_rest_permission(
    state: &IamState,
    id: PermissionId,
) -> Result<Option<RestPermissionView>, Problem> {
    Ok(state.query_bus.ask(GetRestPermissionQuery { id }).await?)
}

/// Lists REST permissions.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 422 for invalid parameters.
#[utoipa::path(
    get,
    path = "/rest-permissions",
    operation_id = "api_rest_permissions_get",
    tag = "iam",
    summary = "Retrieves the collection of REST permissions.",
    description = "Returns one page of the catalogue in a stable order, with the `nextCursor` of the next page. Filters: `service`, `method`, `active`, `sensitive` and `templatePrefix`. Each entry carries its key, service, method, template, flags, active state, the active versions that contain it and the roles that grant it by its exact key.",
    security(("bearerAuth" = [])),
    params(ListRestPermissionsParams),
    responses(
        (status = 200, description = "One page of entries.", body = RestPermissionPageResponse),
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
    ValidatedQuery(params): ValidatedQuery<ListRestPermissionsParams>,
) -> Result<Json<RestPermissionPageResponse>, Problem> {
    Ok(Json(RestPermissionPageResponse::from(
        list_rest_permissions(&state, params).await?,
    )))
}

/// Reads a REST permission.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 404 for an unknown entry, 422 for an id that is
/// not a UUID.
#[utoipa::path(
    get,
    path = "/rest-permissions/{id}",
    operation_id = "api_rest_permissions_id_get",
    tag = "iam",
    summary = "Retrieves a REST permission.",
    description = "Returns the entry with the identifier: its key, service, method, template, flags, active state, the active versions that contain it and the roles that grant it by its exact key.",
    security(("bearerAuth" = [])),
    params(("id" = String, Path, format = Uuid, description = "Permission identifier")),
    responses(
        (status = 200, description = "The entry.", body = RestPermissionResponse),
        (status = 400, description = "Invalid identifier.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 404, description = "Permission not found.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn get_one(
    State(state): State<IamState>,
    CallerPrincipal(_caller): CallerPrincipal,
    ApiPath(id): ApiPath<String>,
) -> Result<Json<RestPermissionResponse>, Problem> {
    let view = find_rest_permission(&state, parse_permission_id(&id)?)
        .await?
        .ok_or(IamError::NotFound)?;
    Ok(Json(RestPermissionResponse::from(view)))
}

#[cfg(test)]
mod tests;
