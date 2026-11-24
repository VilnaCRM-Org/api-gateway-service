//! Wire shapes of the bulk operations.

use iam_domain::{BulkOperationId, BulkOperationParts, PolicyVersion};
use serde::{Deserialize, Serialize};
use shared_application::http::Violation;
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::error::IamError;
use crate::http::dto::DEFAULT_PAGE_SIZE;
use crate::query::list_bulk_operations::{BulkOperationPage, ListBulkOperationsQuery};

/// How far the gateway pods have acknowledged the policy versions of a revocation-class bulk
/// operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = BulkOperationPropagation)]
pub struct BulkPropagationResponse {
    /// `pending`, `acknowledged` or `timed_out`.
    #[schema(example = "acknowledged")]
    pub status: String,
    /// The policy version the status is about.
    #[schema(minimum = 0)]
    pub policy_version: i64,
    /// How many gateway pods acknowledged the version.
    #[schema(minimum = 0)]
    pub pods_acknowledged: i64,
    /// How many gateway pods did not acknowledge it in time.
    #[schema(minimum = 0)]
    pub pods_timed_out: i64,
}

/// A bulk operation: a large change that the runner commits in chunks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = BulkOperation)]
pub struct BulkOperationResponse {
    /// The identifier.
    #[schema(format = Uuid)]
    pub id: String,
    /// What the operation changes: `role_deletion`, `catalogue`, `resync` or `other`.
    #[schema(example = "role_deletion")]
    pub kind: String,
    /// Where it stands: `pending`, `running`, `completed` or `failed`.
    #[schema(example = "running")]
    pub status: String,
    /// How many records the whole change touches.
    #[schema(minimum = 1)]
    pub total_records: i64,
    /// How many records the committed chunks applied.
    #[schema(minimum = 0)]
    pub applied_records: i64,
    /// The policy version of the first committed chunk; absent before the first chunk.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(minimum = 0)]
    pub first_version: Option<i64>,
    /// The policy version of the last committed chunk; absent before the first chunk.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(minimum = 0)]
    pub last_version: Option<i64>,
    /// Who asked for the change.
    #[schema(example = "user:7f0cdd0e-6c1a-4a3b-9f7e-0b8e8f5f5f01")]
    pub requester: String,
    /// Why the operation failed; absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(max_length = 500)]
    pub error: Option<String>,
    /// The propagation of a revocation-class bulk operation; `null` until the chunks of such an
    /// operation are fenced by the pods' acknowledgements.
    pub propagation: Option<BulkPropagationResponse>,
    /// When the operation was recorded, as an RFC 3339 UTC time.
    #[schema(format = DateTime, example = "2027-01-15T08:00:00.000000Z")]
    pub created_at: String,
    /// When the operation last changed, as an RFC 3339 UTC time.
    #[schema(format = DateTime, example = "2027-01-15T08:00:05.000000Z")]
    pub updated_at: String,
}

/// A count as the signed integer of the wire; counts above `i64::MAX` cannot occur.
fn wire_count(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

impl From<BulkOperationParts> for BulkOperationResponse {
    fn from(parts: BulkOperationParts) -> Self {
        Self {
            id: parts.id.to_string(),
            kind: parts.kind.as_str().to_owned(),
            status: parts.status.as_str().to_owned(),
            total_records: wire_count(parts.total_records),
            applied_records: wire_count(parts.applied_records),
            first_version: parts.first_version.map(PolicyVersion::value),
            last_version: parts.last_version.map(PolicyVersion::value),
            requester: parts.requester.to_string(),
            error: parts.error,
            propagation: None,
            created_at: humantime::format_rfc3339_micros(parts.created_at).to_string(),
            updated_at: humantime::format_rfc3339_micros(parts.updated_at).to_string(),
        }
    }
}

/// One page of bulk operations, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = BulkOperationPage)]
pub struct BulkOperationPageResponse {
    /// The operations of the page.
    pub items: Vec<BulkOperationResponse>,
    /// The `after` value of the next page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(format = Uuid)]
    pub next_cursor: Option<String>,
}

impl From<BulkOperationPage> for BulkOperationPageResponse {
    fn from(page: BulkOperationPage) -> Self {
        Self {
            items: page
                .operations
                .into_iter()
                .map(BulkOperationResponse::from)
                .collect(),
            next_cursor: page.next_after.map(|id| id.to_string()),
        }
    }
}

/// Query parameters of the bulk operation list; `limit` is signed so that a negative value is a
/// 422, not a parse error.
#[derive(Debug, Clone, Deserialize, IntoParams, Validate)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ListBulkOperationsParams {
    /// The largest number of operations of the page.
    #[param(minimum = 1, maximum = 100, default = 30)]
    #[validate(range(min = 1, max = 100, message = "This value must be between 1 and 100."))]
    pub limit: i32,
    /// The `nextCursor` of the previous page; absent for the first page.
    #[param(format = Uuid)]
    pub after: Option<String>,
}

impl Default for ListBulkOperationsParams {
    fn default() -> Self {
        Self {
            limit: DEFAULT_PAGE_SIZE,
            after: None,
        }
    }
}

impl ListBulkOperationsParams {
    /// The query for these parameters; call it after validation, which makes `limit` positive.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with a violation of `after` when it is not a UUID.
    pub fn into_query(self) -> Result<ListBulkOperationsQuery, IamError> {
        let after = self
            .after
            .as_deref()
            .map(BulkOperationId::parse)
            .transpose()
            .map_err(|error| {
                IamError::Invalid(vec![Violation {
                    property_path: "after".to_owned(),
                    message: error.to_string(),
                    code: error.code().to_owned(),
                }])
            })?;
        Ok(ListBulkOperationsQuery {
            limit: self.limit.unsigned_abs(),
            after,
        })
    }
}

#[cfg(test)]
mod tests;
