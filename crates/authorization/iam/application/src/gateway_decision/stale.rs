//! The decision API of a gateway whose snapshot is not proven fresh (FR-13, FR-50).
//!
//! The decision listener answers the deny `unavailable` for every check while its snapshot is
//! stale, without authenticating the caller, and without deciding anything: these handlers never
//! consult the snapshot reads or the read-your-writes barrier. They still write the access record
//! that every check of the decision API leaves (Story 14.1), with the decision id that the response
//! carries, so a stale answer is as traceable as a decided one.

use std::sync::Arc;

use iam_domain::{Credential, DecisionOutcome};
use shared_domain::{Query, QueryHandler};
use tokio::time::Instant;

use super::{Recorded, record};
use crate::access_decision_service::AccessDecisionService;
use crate::access_log::{
    BATCH_VALIDATION_TEMPLATE, DecisionAccessLog, DecisionTrace, VALIDATION_TEMPLATE,
};
use crate::error::IamError;
use crate::query::validate_access::ValidateAccessQuery;
use crate::query::validate_access_batch::{BatchCheck, ValidateAccessBatchQuery};

/// Asks for the answer of a stale gateway to one check: the deny `unavailable`, recorded.
#[derive(Debug, Clone)]
pub struct ValidateAccessStaleQuery(pub ValidateAccessQuery);

impl Query for ValidateAccessStaleQuery {
    type Output = DecisionOutcome;
    type Error = IamError;
    const NAME: &'static str = "ValidateAccessStaleQuery";
}

/// Asks for the answer of a stale gateway to a batch: one recorded deny per item.
#[derive(Debug, Clone)]
pub struct ValidateAccessStaleBatchQuery(pub ValidateAccessBatchQuery);

impl Query for ValidateAccessStaleBatchQuery {
    type Output = Vec<DecisionOutcome>;
    type Error = IamError;
    const NAME: &'static str = "ValidateAccessStaleBatchQuery";
}

/// Handles [`ValidateAccessStaleQuery`].
#[derive(Debug)]
pub struct StaleValidateAccessQueryHandler {
    decisions: Arc<AccessDecisionService>,
    access_log: Option<Arc<DecisionAccessLog>>,
}

impl StaleValidateAccessQueryHandler {
    /// A handler that builds its denials with `decisions`.
    #[must_use]
    pub const fn new(decisions: Arc<AccessDecisionService>) -> Self {
        Self {
            decisions,
            access_log: None,
        }
    }

    /// The same handler recording every check in the access log (FR-50).
    #[must_use]
    pub fn with_access_log(mut self, access_log: Arc<DecisionAccessLog>) -> Self {
        self.access_log = Some(access_log);
        self
    }

    fn answer(&self, query: &ValidateAccessQuery) -> DecisionOutcome {
        let started = Instant::now();
        let outcome = self.decisions.unavailable();
        record(
            self.access_log.as_deref(),
            &Recorded {
                template: VALIDATION_TEMPLATE,
                credential: &query.credential,
                check: Some(&query.check),
                outcome: &outcome,
                trace: &DecisionTrace::default(),
            },
            started,
        );
        outcome
    }
}

#[async_trait::async_trait]
impl QueryHandler<ValidateAccessStaleQuery> for StaleValidateAccessQueryHandler {
    async fn handle(&self, query: ValidateAccessStaleQuery) -> Result<DecisionOutcome, IamError> {
        Ok(self.answer(&query.0))
    }
}

/// Handles [`ValidateAccessStaleBatchQuery`].
#[derive(Debug)]
pub struct StaleValidateAccessBatchQueryHandler {
    decisions: Arc<AccessDecisionService>,
    access_log: Option<Arc<DecisionAccessLog>>,
}

impl StaleValidateAccessBatchQueryHandler {
    /// A handler that builds its denials with `decisions`.
    #[must_use]
    pub const fn new(decisions: Arc<AccessDecisionService>) -> Self {
        Self {
            decisions,
            access_log: None,
        }
    }

    /// The same handler recording every item in the access log (FR-50).
    #[must_use]
    pub fn with_access_log(mut self, access_log: Arc<DecisionAccessLog>) -> Self {
        self.access_log = Some(access_log);
        self
    }

    fn answer(&self, query: &ValidateAccessBatchQuery) -> Vec<DecisionOutcome> {
        query
            .checks
            .iter()
            .map(|item| self.answer_item(item))
            .collect()
    }

    /// The deny `unavailable` for a readable item and `malformed_operation` for one that could not
    /// be read, as on a fresh gateway.
    fn answer_item(&self, item: &BatchCheck) -> DecisionOutcome {
        let started = Instant::now();
        let BatchCheck::Valid(query) = item else {
            let outcome = self.decisions.malformed();
            self.record_item(&Credential::new(String::new()), None, &outcome, started);
            return outcome;
        };
        let outcome = self.decisions.unavailable();
        self.record_item(&query.credential, Some(&query.check), &outcome, started);
        outcome
    }

    fn record_item(
        &self,
        credential: &Credential,
        check: Option<&iam_domain::AccessCheck>,
        outcome: &DecisionOutcome,
        started: Instant,
    ) {
        record(
            self.access_log.as_deref(),
            &Recorded {
                template: BATCH_VALIDATION_TEMPLATE,
                credential,
                check,
                outcome,
                trace: &DecisionTrace::default(),
            },
            started,
        );
    }
}

#[async_trait::async_trait]
impl QueryHandler<ValidateAccessStaleBatchQuery> for StaleValidateAccessBatchQueryHandler {
    async fn handle(
        &self,
        query: ValidateAccessStaleBatchQuery,
    ) -> Result<Vec<DecisionOutcome>, IamError> {
        Ok(self.answer(&query.0))
    }
}

#[cfg(test)]
mod tests;
