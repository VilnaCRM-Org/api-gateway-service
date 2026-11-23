//! REST handlers that read the GraphQL permission catalogue, and the use-case calls that the
//! GraphQL resolvers share.
//!
//! A handler takes the IAM state and the problem-aware extractors only (`ApiPath`,
//! `ValidatedQuery` and the IAM extractor `CallerPrincipal`); the test of the `handler` module
//! checks every handler against that rule.

pub mod dto;

use axum::Json;
use axum::extract::State;
use iam_domain::PermissionId;
use shared_application::http::{ApiPath, Problem, ValidatedQuery, Violation};

use super::IamState;
use super::extract::CallerPrincipal;
use crate::error::IamError;
use crate::query::get_graphql_permission::GetGraphQlPermissionQuery;
use crate::query::get_graphql_permissions::{GraphQlPermissionPage, GraphQlPermissionView};
use dto::{GraphQlPermissionPageResponse, GraphQlPermissionResponse, ListGraphQlPermissionsParams};

/// The entry id of a path or an argument.
///
/// # Errors
///
/// [`IamError::Invalid`] with a violation of `id` when the text is not a UUID.
pub(crate) fn parse_permission_id(text: &str) -> Result<PermissionId, IamError> {
    PermissionId::parse(text).map_err(|_error| {
        IamError::Invalid(vec![Violation {
            property_path: "id".to_owned(),
            message: "This value is not a valid UUID.".to_owned(),
            code: "uuid".to_owned(),
        }])
    })
}

/// One page of entries for validated parameters.
///
/// # Errors
///
/// The 422 problem of an invalid cursor, service or type, the 500 problem of a storage failure.
pub(crate) async fn list_graphql_permissions(
    state: &IamState,
    params: ListGraphQlPermissionsParams,
) -> Result<GraphQlPermissionPage, Problem> {
    Ok(state.query_bus.ask(params.into_query()?).await?)
}

/// The entry with the identifier, with its versions and roles; none when it is unknown.
///
/// # Errors
///
/// The 500 problem of a storage failure.
pub(crate) async fn find_graphql_permission(
    state: &IamState,
    id: PermissionId,
) -> Result<Option<GraphQlPermissionView>, Problem> {
    Ok(state
        .query_bus
        .ask(GetGraphQlPermissionQuery { id })
        .await?)
}

/// Lists GraphQL permissions.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 422 for invalid parameters.
#[utoipa::path(
    get,
    path = "/graphql-permissions",
    operation_id = "api_graphql_permissions_get",
    tag = "iam",
    summary = "Retrieves the collection of GraphQL permissions.",
    description = "Returns one page of the catalogue in a stable order, with the `nextCursor` of the next page. Filters: `service`, `type`, `active`, `sensitive` and `keyPrefix`. Each entry carries its key, service, type, field, flags, active state, the active versions that contain it and the roles that grant it by its exact key.",
    security(("bearerAuth" = [])),
    params(ListGraphQlPermissionsParams),
    responses(
        (status = 200, description = "One page of entries.", body = GraphQlPermissionPageResponse),
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
    ValidatedQuery(params): ValidatedQuery<ListGraphQlPermissionsParams>,
) -> Result<Json<GraphQlPermissionPageResponse>, Problem> {
    Ok(Json(GraphQlPermissionPageResponse::from(
        list_graphql_permissions(&state, params).await?,
    )))
}

/// Reads a GraphQL permission.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 404 for an unknown entry, 422 for an id that is
/// not a UUID.
#[utoipa::path(
    get,
    path = "/graphql-permissions/{id}",
    operation_id = "api_graphql_permissions_id_get",
    tag = "iam",
    summary = "Retrieves a GraphQL permission.",
    description = "Returns the entry with the identifier: its key, service, type, field, flags, active state, the active versions that contain it and the roles that grant it by its exact key.",
    security(("bearerAuth" = [])),
    params(("id" = String, Path, format = Uuid, description = "Permission identifier")),
    responses(
        (status = 200, description = "The entry.", body = GraphQlPermissionResponse),
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
) -> Result<Json<GraphQlPermissionResponse>, Problem> {
    let view = find_graphql_permission(&state, parse_permission_id(&id)?)
        .await?
        .ok_or(IamError::NotFound)?;
    Ok(Json(GraphQlPermissionResponse::from(view)))
}

#[cfg(test)]
mod tests;
