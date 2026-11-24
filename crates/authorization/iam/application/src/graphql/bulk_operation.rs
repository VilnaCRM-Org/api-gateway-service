//! GraphQL objects and the resolvers of the bulk operations.
//!
//! The resolvers share the use-case calls and the response shapes of the REST handlers, so both
//! transports apply one set of rules.

use async_graphql::{Context, ID, SimpleObject};
use shared_application::http::Problem;
use validator::Validate as _;

use super::{require_caller, state};
use crate::http::bulk_operation::dto::{
    BulkOperationPageResponse, BulkOperationResponse, BulkPropagationResponse,
    ListBulkOperationsParams,
};
use crate::http::bulk_operation::{
    find_bulk_operation, list_bulk_operations, parse_bulk_operation_id,
};
use crate::http::dto::DEFAULT_PAGE_SIZE;

/// How far the gateway pods have acknowledged the policy versions of a revocation-class bulk
/// operation.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "BulkOperationPropagation")]
pub struct BulkPropagationObject {
    /// `pending`, `acknowledged` or `timed_out`.
    pub status: String,
    /// The policy version the status is about.
    pub policy_version: i64,
    /// How many gateway pods acknowledged the version.
    pub pods_acknowledged: i64,
    /// How many gateway pods did not acknowledge it in time.
    pub pods_timed_out: i64,
}

impl From<BulkPropagationResponse> for BulkPropagationObject {
    fn from(response: BulkPropagationResponse) -> Self {
        Self {
            status: response.status,
            policy_version: response.policy_version,
            pods_acknowledged: response.pods_acknowledged,
            pods_timed_out: response.pods_timed_out,
        }
    }
}

/// A bulk operation: a large change that the runner commits in chunks.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "BulkOperation")]
pub struct BulkOperationObject {
    /// The identifier.
    pub id: ID,
    /// What the operation changes: `role_deletion`, `catalogue`, `resync` or `other`.
    pub kind: String,
    /// Where it stands: `pending`, `running`, `completed` or `failed`.
    pub status: String,
    /// How many records the whole change touches.
    pub total_records: i64,
    /// How many records the committed chunks applied.
    pub applied_records: i64,
    /// The policy version of the first committed chunk; null before the first chunk.
    pub first_version: Option<i64>,
    /// The policy version of the last committed chunk; null before the first chunk.
    pub last_version: Option<i64>,
    /// Who asked for the change.
    pub requester: String,
    /// Why the operation failed; null otherwise.
    pub error: Option<String>,
    /// The propagation of a revocation-class bulk operation; null until the chunks of such an operation are fenced by the pods' acknowledgements.
    pub propagation: Option<BulkPropagationObject>,
    /// When the operation was recorded, as an RFC 3339 UTC time.
    pub created_at: String,
    /// When the operation last changed, as an RFC 3339 UTC time.
    pub updated_at: String,
}

impl From<BulkOperationResponse> for BulkOperationObject {
    fn from(response: BulkOperationResponse) -> Self {
        Self {
            id: ID::from(response.id),
            kind: response.kind,
            status: response.status,
            total_records: response.total_records,
            applied_records: response.applied_records,
            first_version: response.first_version,
            last_version: response.last_version,
            requester: response.requester,
            error: response.error,
            propagation: response.propagation.map(BulkPropagationObject::from),
            created_at: response.created_at,
            updated_at: response.updated_at,
        }
    }
}

/// One page of bulk operations.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "BulkOperationPage")]
pub struct BulkOperationPageObject {
    /// The operations of the page, oldest first.
    pub items: Vec<BulkOperationObject>,
    /// The `after` value of the next page; null on the last page.
    pub next_cursor: Option<String>,
}

impl From<BulkOperationPageResponse> for BulkOperationPageObject {
    fn from(page: BulkOperationPageResponse) -> Self {
        Self {
            items: page
                .items
                .into_iter()
                .map(BulkOperationObject::from)
                .collect(),
            next_cursor: page.next_cursor,
        }
    }
}

/// Reads one bulk operation; none when it is unknown.
pub(super) async fn bulk_operation_field(
    ctx: &Context<'_>,
    id: &ID,
) -> Result<Option<BulkOperationObject>, Problem> {
    require_caller(ctx)?;
    let operation = find_bulk_operation(state(ctx)?, parse_bulk_operation_id(id.as_str())?).await?;
    Ok(operation.map(|parts| BulkOperationObject::from(BulkOperationResponse::from(parts))))
}

/// Reads one page of bulk operations.
pub(super) async fn bulk_operations_field(
    ctx: &Context<'_>,
    first: Option<i32>,
    after: Option<String>,
) -> Result<BulkOperationPageObject, Problem> {
    require_caller(ctx)?;
    let params = ListBulkOperationsParams {
        limit: first.unwrap_or(DEFAULT_PAGE_SIZE),
        after,
    };
    params.validate()?;
    let page = list_bulk_operations(state(ctx)?, params).await?;
    Ok(BulkOperationPageObject::from(
        BulkOperationPageResponse::from(page),
    ))
}

#[cfg(test)]
mod tests;
