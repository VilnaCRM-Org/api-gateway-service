//! Decides up to 100 access checks in one call (FR-11).

pub(crate) mod token_memo;

use std::sync::Arc;

use iam_domain::{DecisionOutcome, PolicyEpochRepository, TokenRepository};
use shared_domain::{Query, QueryHandler};

use crate::access_decision_service::AccessDecisionService;
use crate::error::IamError;
use crate::query::validate_access::{MinimumVersion, ValidateAccessQuery, check_minimum};
use token_memo::BatchTokenMemo;

/// One item of a batch.
#[derive(Debug, Clone)]
pub enum BatchCheck {
    /// An item that parsed: the check is decided independently of the others.
    Valid(ValidateAccessQuery),
    /// An item that could not be read; it is decided as the deny `malformed_operation`.
    Malformed,
}

/// Asks the questions of a batch, in request order.
#[derive(Debug, Clone)]
pub struct ValidateAccessBatchQuery {
    /// The items of the batch, one decision each.
    pub checks: Vec<BatchCheck>,
}

impl Query for ValidateAccessBatchQuery {
    type Output = Vec<DecisionOutcome>;
    type Error = IamError;
    const NAME: &'static str = "ValidateAccessBatchQuery";
}

/// Handles [`ValidateAccessBatchQuery`].
///
/// Every item gets its own decision, in request order, from the decision path of
/// [`ValidateAccessQueryHandler`](crate::query::validate_access::ValidateAccessQueryHandler). An
/// item that could not be read, or that names a policy version that IAM has not issued yet, is
/// the deny `malformed_operation` and never fails the others. Each distinct credential is resolved
/// once per batch.
#[derive(Debug)]
pub struct ValidateAccessBatchQueryHandler {
    decisions: Arc<AccessDecisionService>,
    epochs: Arc<dyn PolicyEpochRepository>,
    tokens: Arc<dyn TokenRepository>,
}

impl ValidateAccessBatchQueryHandler {
    /// A handler over the decision path, the policy epoch and the token repository that the
    /// decision path resolves credentials through.
    #[must_use]
    pub const fn new(
        decisions: Arc<AccessDecisionService>,
        epochs: Arc<dyn PolicyEpochRepository>,
        tokens: Arc<dyn TokenRepository>,
    ) -> Self {
        Self {
            decisions,
            epochs,
            tokens,
        }
    }

    async fn validate(&self, query: &ValidateAccessBatchQuery) -> Vec<DecisionOutcome> {
        let memo = BatchTokenMemo::new(Arc::clone(&self.tokens));
        let mut outcomes = Vec::with_capacity(query.checks.len());
        for check in &query.checks {
            outcomes.push(self.decide_item(&memo, check).await);
        }
        outcomes
    }

    async fn decide_item(&self, memo: &BatchTokenMemo, item: &BatchCheck) -> DecisionOutcome {
        let BatchCheck::Valid(query) = item else {
            return self.decisions.malformed();
        };
        match check_minimum(self.epochs.as_ref(), &query.check).await {
            MinimumVersion::Held => {
                self.decisions
                    .decide_with(memo, &query.credential, &query.check)
                    .await
            }
            MinimumVersion::Unissued => self.decisions.malformed(),
            MinimumVersion::Unreadable => self.decisions.unavailable(),
        }
    }
}

#[async_trait::async_trait]
impl QueryHandler<ValidateAccessBatchQuery> for ValidateAccessBatchQueryHandler {
    async fn handle(
        &self,
        query: ValidateAccessBatchQuery,
    ) -> Result<Vec<DecisionOutcome>, IamError> {
        Ok(self.validate(&query).await)
    }
}

#[cfg(test)]
mod tests;
