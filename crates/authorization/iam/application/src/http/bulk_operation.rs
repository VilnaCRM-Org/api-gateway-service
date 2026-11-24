//! REST handlers of the bulk operations, and the use-case calls that the GraphQL resolvers share.
//!
//! A handler takes the IAM state and the problem-aware extractors only (`ApiPath`,
//! `ValidatedQuery`, the IAM extractor `CallerPrincipal`); the test of the `handler` module checks
//! every handler against that rule.

pub mod dto;

use axum::Json;
use axum::extract::State;
use iam_domain::{BulkOperationId, BulkOperationParts};
use shared_application::http::{ApiPath, Problem, ValidatedQuery, Violation};

use super::IamState;
use super::extract::CallerPrincipal;
use crate::error::IamError;
use crate::query::get_bulk_operation::GetBulkOperationQuery;
use crate::query::list_bulk_operations::BulkOperationPage;
use dto::{BulkOperationPageResponse, BulkOperationResponse, ListBulkOperationsParams};

/// The path of the bulk operation collection, under which a bulk change has its `Location`.
pub const BULK_OPERATIONS_PATH: &str = "/api/bulk-operations";

/// The bulk operation id of a path or an argument.
///
/// # Errors
///
/// [`IamError::Invalid`] with a violation of `id` when the text is not a UUID.
pub(crate) fn parse_bulk_operation_id(text: &str) -> Result<BulkOperationId, IamError> {
    BulkOperationId::parse(text).map_err(|_error| {
        IamError::Invalid(vec![Violation {
            property_path: "id".to_owned(),
            message: "This value is not a valid UUID.".to_owned(),
            code: "uuid".to_owned(),
        }])
    })
}

/// The bulk operation with the identifier, none when it is unknown.
///
/// # Errors
///
/// The 500 problem of a storage failure.
pub(crate) async fn find_bulk_operation(
    state: &IamState,
    id: BulkOperationId,
) -> Result<Option<BulkOperationParts>, Problem> {
    Ok(state.query_bus.ask(GetBulkOperationQuery { id }).await?)
}

/// One page of bulk operations for validated parameters.
///
/// # Errors
///
/// The 422 problem of an invalid cursor, the 500 problem of a storage failure.
pub(crate) async fn list_bulk_operations(
    state: &IamState,
    params: ListBulkOperationsParams,
) -> Result<BulkOperationPage, Problem> {
    Ok(state.query_bus.ask(params.into_query()?).await?)
}

/// Reads a bulk operation.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without the catalogue key, 404 for an
/// unknown operation, 422 for an id that is not a UUID.
#[utoipa::path(
    get,
    path = "/bulk-operations/{id}",
    operation_id = "api_bulk_operations_id_get",
    tag = "iam",
    summary = "Retrieves a bulk operation.",
    description = "Returns the bulk operation with the identifier: its kind, status, applied and total records, the policy versions of its first and last chunk, its requester and, for a failed operation, its error. `propagation` is `null` until the chunks of a revocation-class operation are fenced by the pods' acknowledgements.",
    security(("bearerAuth" = [])),
    params(("id" = String, Path, format = Uuid, description = "Bulk operation identifier")),
    responses(
        (status = 200, description = "The bulk operation.", body = BulkOperationResponse),
        (status = 400, description = "Invalid identifier.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 403, description = "The caller does not hold the key of the operation.", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Bulk operation not found.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn get_one(
    State(state): State<IamState>,
    CallerPrincipal(_caller): CallerPrincipal,
    ApiPath(id): ApiPath<String>,
) -> Result<Json<BulkOperationResponse>, Problem> {
    let operation = find_bulk_operation(&state, parse_bulk_operation_id(&id)?)
        .await?
        .ok_or(IamError::NotFound)?;
    Ok(Json(BulkOperationResponse::from(operation)))
}

/// Lists bulk operations.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without the catalogue key, 422 for an
/// invalid limit or cursor.
#[utoipa::path(
    get,
    path = "/bulk-operations",
    operation_id = "api_bulk_operations_get",
    tag = "iam",
    summary = "Retrieves the collection of bulk operations.",
    description = "Returns one page of bulk operations, oldest first, with the `nextCursor` of the next page.",
    security(("bearerAuth" = [])),
    params(ListBulkOperationsParams),
    responses(
        (status = 200, description = "One page of bulk operations.", body = BulkOperationPageResponse),
        (status = 400, description = "Invalid query parameter.", body = Problem, content_type = "application/problem+json"),
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
    ValidatedQuery(params): ValidatedQuery<ListBulkOperationsParams>,
) -> Result<Json<BulkOperationPageResponse>, Problem> {
    Ok(Json(BulkOperationPageResponse::from(
        list_bulk_operations(&state, params).await?,
    )))
}

#[cfg(test)]
mod tests;
