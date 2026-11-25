//! The decision handlers of the gateway's decision API (FR-6, FR-11, FR-14, FR-19).
//!
//! They answer [`ValidateAccessQuery`] and [`ValidateAccessBatchQuery`] over the same
//! [`AccessDecisionService`] as `iam-control`, fed from the snapshot through
//! [`SnapshotPolicyReads`]. Where `iam-control` compares `minPolicyVersion` with the policy epoch of
//! PostgreSQL and refuses an unissued version with 422, the gateway cannot tell an unissued version
//! from one it has not received yet, and the decision API always answers with a decision body: a
//! check is decided only on a fresh snapshot of at least the version it names, and every other check
//! is the deny `unavailable`.
//!
//! A GraphQL document target is the deny `unavailable` as well, because the snapshot carries no
//! return types to analyse it against (see [`crate::snapshot_policy_reads`]).

use std::sync::Arc;

use iam_domain::{AccessCheck, AccessTarget, Credential, DecisionOutcome, TokenRepository};
use shared_domain::QueryHandler;
use tokio::time::Instant;

use crate::access_decision_service::AccessDecisionService;
use crate::access_log::{
    BATCH_VALIDATION_TEMPLATE, DecisionAccessLog, DecisionCall, DecisionTrace, VALIDATION_TEMPLATE,
};
use crate::error::IamError;
use crate::query::validate_access::ValidateAccessQuery;
use crate::query::validate_access_batch::token_memo::BatchTokenMemo;
use crate::query::validate_access_batch::{BatchCheck, ValidateAccessBatchQuery};
use crate::read_your_writes::{BarrierVerdict, ReadYourWritesBarrier};
use crate::snapshot_policy_reads::SnapshotPolicyReads;

pub mod stale;

/// The barrier of a check and the instant at which its wait ends; a batch gives every item the
/// same instant, so the whole batch waits at most one barrier timeout.
type Barred<'barrier> = Option<(&'barrier ReadYourWritesBarrier, Instant)>;

/// Whether the snapshot can decide a check.
///
/// With a `barrier`, a `minPolicyVersion` above the highest version the pod has seen is refused
/// at once and one the pod has seen but not published waits for its snapshot, up to the deadline of
/// the barrier; a timeout is a refusal too, because the decision API always answers with a
/// decision body. Without one, the version must be held by the snapshot now.
async fn decidable(reads: &SnapshotPolicyReads, barrier: Barred<'_>, check: &AccessCheck) -> bool {
    if matches!(check.target(), AccessTarget::GraphQl(_)) {
        return false;
    }
    if reads.serving().is_err() {
        return false;
    }
    let Some(minimum) = check.min_policy_version() else {
        return true;
    };
    let admitted = match barrier {
        Some((barrier, deadline)) => {
            barrier.admit_by(minimum, deadline).await == BarrierVerdict::Proceed
        }
        None => true,
    };
    admitted
        && reads
            .serving()
            .is_ok_and(|snapshot| minimum <= snapshot.version())
}

/// Handles [`ValidateAccessQuery`] on the gateway.
#[derive(Debug)]
pub struct GatewayValidateAccessQueryHandler {
    decisions: Arc<AccessDecisionService>,
    reads: Arc<SnapshotPolicyReads>,
    barrier: Option<Arc<ReadYourWritesBarrier>>,
    access_log: Option<Arc<DecisionAccessLog>>,
}

impl GatewayValidateAccessQueryHandler {
    /// A handler over the decision path and the snapshot reads that feed it.
    #[must_use]
    pub const fn new(
        decisions: Arc<AccessDecisionService>,
        reads: Arc<SnapshotPolicyReads>,
    ) -> Self {
        Self {
            decisions,
            reads,
            barrier: None,
            access_log: None,
        }
    }

    /// The same handler recording every check in the access log (FR-50).
    #[must_use]
    pub fn with_access_log(mut self, access_log: Arc<DecisionAccessLog>) -> Self {
        self.access_log = Some(access_log);
        self
    }

    /// The same handler with the read-your-writes barrier of `minPolicyVersion` (FR-14).
    #[must_use]
    pub fn with_barrier(mut self, barrier: Arc<ReadYourWritesBarrier>) -> Self {
        self.barrier = Some(barrier);
        self
    }

    async fn validate(&self, query: &ValidateAccessQuery) -> DecisionOutcome {
        let started = Instant::now();
        let barred = self
            .barrier
            .as_deref()
            .map(|barrier| (barrier, barrier.deadline()));
        let (outcome, trace) = if decidable(&self.reads, barred, &query.check).await {
            self.decisions
                .decide_traced(&query.credential, &query.check)
                .await
        } else {
            (self.decisions.unavailable(), DecisionTrace::default())
        };
        record(
            self.access_log.as_deref(),
            &Recorded {
                template: VALIDATION_TEMPLATE,
                credential: &query.credential,
                check: Some(&query.check),
                outcome: &outcome,
                trace: &trace,
            },
            started,
        );
        outcome
    }
}

#[async_trait::async_trait]
impl QueryHandler<ValidateAccessQuery> for GatewayValidateAccessQueryHandler {
    async fn handle(&self, query: ValidateAccessQuery) -> Result<DecisionOutcome, IamError> {
        Ok(self.validate(&query).await)
    }
}

/// Handles [`ValidateAccessBatchQuery`] on the gateway.
///
/// Every item gets its own decision in request order, and each distinct credential is resolved once
/// per batch, as on `iam-control`.
#[derive(Debug)]
pub struct GatewayValidateAccessBatchQueryHandler {
    decisions: Arc<AccessDecisionService>,
    reads: Arc<SnapshotPolicyReads>,
    tokens: Arc<dyn TokenRepository>,
    barrier: Option<Arc<ReadYourWritesBarrier>>,
    access_log: Option<Arc<DecisionAccessLog>>,
}

impl GatewayValidateAccessBatchQueryHandler {
    /// A handler over the decision path, the snapshot reads that feed it and the token repository
    /// the decision path resolves credentials through.
    #[must_use]
    pub const fn new(
        decisions: Arc<AccessDecisionService>,
        reads: Arc<SnapshotPolicyReads>,
        tokens: Arc<dyn TokenRepository>,
    ) -> Self {
        Self {
            decisions,
            reads,
            tokens,
            barrier: None,
            access_log: None,
        }
    }

    /// The same handler recording every check in the access log (FR-50).
    #[must_use]
    pub fn with_access_log(mut self, access_log: Arc<DecisionAccessLog>) -> Self {
        self.access_log = Some(access_log);
        self
    }

    /// The same handler with the read-your-writes barrier of `minPolicyVersion` (FR-14).
    #[must_use]
    pub fn with_barrier(mut self, barrier: Arc<ReadYourWritesBarrier>) -> Self {
        self.barrier = Some(barrier);
        self
    }

    async fn validate(&self, query: &ValidateAccessBatchQuery) -> Vec<DecisionOutcome> {
        let memo = BatchTokenMemo::new(Arc::clone(&self.tokens));
        let barred = self
            .barrier
            .as_deref()
            .map(|barrier| (barrier, barrier.deadline()));
        let mut outcomes = Vec::with_capacity(query.checks.len());
        for item in &query.checks {
            outcomes.push(self.decide_item(&memo, barred, item).await);
        }
        outcomes
    }

    async fn decide_item(
        &self,
        memo: &BatchTokenMemo,
        barred: Barred<'_>,
        item: &BatchCheck,
    ) -> DecisionOutcome {
        let started = Instant::now();
        let BatchCheck::Valid(query) = item else {
            let outcome = self.decisions.malformed();
            let blank = Credential::new(String::new());
            record(
                self.access_log.as_deref(),
                &Recorded {
                    template: BATCH_VALIDATION_TEMPLATE,
                    credential: &blank,
                    check: None,
                    outcome: &outcome,
                    trace: &DecisionTrace::default(),
                },
                started,
            );
            return outcome;
        };
        let (outcome, trace) = if decidable(&self.reads, barred, &query.check).await {
            self.decisions
                .decide_traced_with(memo, &query.credential, &query.check)
                .await
        } else {
            (self.decisions.unavailable(), DecisionTrace::default())
        };
        record(
            self.access_log.as_deref(),
            &Recorded {
                template: BATCH_VALIDATION_TEMPLATE,
                credential: &query.credential,
                check: Some(&query.check),
                outcome: &outcome,
                trace: &trace,
            },
            started,
        );
        outcome
    }
}

#[async_trait::async_trait]
impl QueryHandler<ValidateAccessBatchQuery> for GatewayValidateAccessBatchQueryHandler {
    async fn handle(
        &self,
        query: ValidateAccessBatchQuery,
    ) -> Result<Vec<DecisionOutcome>, IamError> {
        Ok(self.validate(&query).await)
    }
}

/// What one check of the decision API leaves for the access log.
struct Recorded<'check> {
    template: &'static str,
    credential: &'check Credential,
    check: Option<&'check AccessCheck>,
    outcome: &'check DecisionOutcome,
    trace: &'check DecisionTrace,
}

/// Records a check when the handler has an access log; the time since `started` is its latency.
fn record(log: Option<&DecisionAccessLog>, recorded: &Recorded<'_>, started: Instant) {
    if let Some(log) = log {
        log.record(&DecisionCall {
            template: recorded.template,
            credential: recorded.credential,
            check: recorded.check,
            outcome: recorded.outcome,
            trace: recorded.trace,
            latency: started.elapsed(),
        });
    }
}

#[cfg(test)]
mod tests;
