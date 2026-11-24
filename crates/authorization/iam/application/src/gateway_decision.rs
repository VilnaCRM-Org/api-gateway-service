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

use iam_domain::{AccessCheck, AccessTarget, DecisionOutcome, TokenRepository};
use shared_domain::QueryHandler;

use crate::access_decision_service::AccessDecisionService;
use crate::error::IamError;
use crate::query::validate_access::ValidateAccessQuery;
use crate::query::validate_access_batch::token_memo::BatchTokenMemo;
use crate::query::validate_access_batch::{BatchCheck, ValidateAccessBatchQuery};
use crate::snapshot_policy_reads::SnapshotPolicyReads;

/// Whether the snapshot can decide a check.
fn decidable(reads: &SnapshotPolicyReads, check: &AccessCheck) -> bool {
    if matches!(check.target(), AccessTarget::GraphQl(_)) {
        return false;
    }
    let Ok(snapshot) = reads.serving() else {
        return false;
    };
    check
        .min_policy_version()
        .is_none_or(|minimum| minimum <= snapshot.version())
}

/// Handles [`ValidateAccessQuery`] on the gateway.
#[derive(Debug)]
pub struct GatewayValidateAccessQueryHandler {
    decisions: Arc<AccessDecisionService>,
    reads: Arc<SnapshotPolicyReads>,
}

impl GatewayValidateAccessQueryHandler {
    /// A handler over the decision path and the snapshot reads that feed it.
    #[must_use]
    pub const fn new(
        decisions: Arc<AccessDecisionService>,
        reads: Arc<SnapshotPolicyReads>,
    ) -> Self {
        Self { decisions, reads }
    }

    async fn validate(&self, query: &ValidateAccessQuery) -> DecisionOutcome {
        if decidable(&self.reads, &query.check) {
            self.decisions.decide(&query.credential, &query.check).await
        } else {
            self.decisions.unavailable()
        }
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
        }
    }

    async fn validate(&self, query: &ValidateAccessBatchQuery) -> Vec<DecisionOutcome> {
        let memo = BatchTokenMemo::new(Arc::clone(&self.tokens));
        let mut outcomes = Vec::with_capacity(query.checks.len());
        for item in &query.checks {
            outcomes.push(self.decide_item(&memo, item).await);
        }
        outcomes
    }

    async fn decide_item(&self, memo: &BatchTokenMemo, item: &BatchCheck) -> DecisionOutcome {
        let BatchCheck::Valid(query) = item else {
            return self.decisions.malformed();
        };
        if decidable(&self.reads, &query.check) {
            self.decisions
                .decide_with(memo, &query.credential, &query.check)
                .await
        } else {
            self.decisions.unavailable()
        }
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

#[cfg(test)]
mod tests;
