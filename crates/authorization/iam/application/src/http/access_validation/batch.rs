//! Wire shapes of the batch access-validation operation of the IAM context.
//!
//! The batch is validated as a whole only for its size; each item is read on its own, so an item
//! that breaks a rule is decided as a deny and never fails the others (FR-11).

use iam_domain::DecisionOutcome;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::{Validate, ValidationError, ValidationErrors};

use super::dto::{AccessValidationResponse, ValidateAccessRequest};
use crate::query::validate_access_batch::{BatchCheck, ValidateAccessBatchQuery};

/// Body of the batch access-validation operation: 1 to 100 checks of the single-check shape.
///
/// Its `Debug` output never shows a credential.
#[derive(Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
#[schema(as = ValidateAccessBatchRequest)]
pub struct ValidateAccessBatchRequest {
    /// The checks to decide, 1 to 100; each one has the shape of the single check, and the
    /// results come back in this order. A check that breaks a rule of its own is decided as a
    /// `deny` with the reason `malformed_operation` and does not fail the others.
    #[schema(min_items = 1, max_items = 100)]
    pub checks: Vec<ValidateAccessRequest>,
}

/// The fewest and the most checks of a batch.
const BATCH_SIZE: std::ops::RangeInclusive<usize> = 1..=100;

/// A batch of no check or of more than 100 is refused as a whole; the items are not validated
/// here, because an item that breaks a rule is decided as a deny and does not fail the others.
impl Validate for ValidateAccessBatchRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if BATCH_SIZE.contains(&self.checks.len()) {
            return Ok(());
        }
        let mut errors = ValidationErrors::new();
        errors.add(
            "checks",
            ValidationError::new("length")
                .with_message("This collection must contain between 1 and 100 elements.".into()),
        );
        Err(errors)
    }
}

impl std::fmt::Debug for ValidateAccessBatchRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidateAccessBatchRequest")
            .finish_non_exhaustive()
    }
}

/// A batch once read: the query to ask and the request id to echo for each item.
#[derive(Debug, Clone)]
pub struct ParsedBatch {
    /// The questions for the decision path, in request order.
    pub query: ValidateAccessBatchQuery,
    /// The request id of each item as the caller sent it, in request order.
    pub request_ids: Vec<String>,
}

impl ValidateAccessBatchRequest {
    /// Reads every item; an item that fails its validation or its parsing becomes a malformed one.
    #[must_use]
    pub fn parse(self) -> ParsedBatch {
        let mut checks = Vec::with_capacity(self.checks.len());
        let mut request_ids = Vec::with_capacity(self.checks.len());
        for item in self.checks {
            request_ids.push(item.request_id.clone());
            checks.push(read_item(item));
        }
        ParsedBatch {
            query: ValidateAccessBatchQuery { checks },
            request_ids,
        }
    }
}

/// One item of the batch: the check when it validates and parses, a malformed one otherwise.
fn read_item(item: ValidateAccessRequest) -> BatchCheck {
    if item.validate().is_err() {
        return BatchCheck::Malformed;
    }
    item.parse().map_or(BatchCheck::Malformed, |parsed| {
        BatchCheck::Valid(parsed.query)
    })
}

/// The results of the batch access-validation operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[schema(as = AccessValidationBatch)]
pub struct AccessValidationBatchResponse {
    /// One decision per check, in the order of the request; each has its own `decisionId`.
    pub results: Vec<AccessValidationResponse>,
}

impl AccessValidationBatchResponse {
    /// The results for `outcomes`, each echoing the request id of the item at its position.
    #[must_use]
    pub fn new(outcomes: &[DecisionOutcome], request_ids: Vec<String>) -> Self {
        Self {
            results: outcomes
                .iter()
                .zip(request_ids)
                .map(|(outcome, request_id)| AccessValidationResponse::echoing(outcome, request_id))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests;
