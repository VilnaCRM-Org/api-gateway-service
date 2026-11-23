//! Decides one access check for a subject's credential (FR-6, FR-13, FR-14).

use std::sync::Arc;

use iam_domain::{AccessCheck, Credential, DecisionOutcome, PolicyEpochRepository};
use shared_domain::{Query, QueryHandler};

use crate::access_decision_service::AccessDecisionService;
use crate::error::IamError;

/// Asks whether the bearer of a credential may do what a check names.
#[derive(Debug, Clone)]
pub struct ValidateAccessQuery {
    /// The subject's token as the caller received it; blank when the caller sent an empty one.
    pub credential: Credential,
    /// The target service, the target, the project and the policy version to reflect.
    pub check: AccessCheck,
}

impl Query for ValidateAccessQuery {
    type Output = DecisionOutcome;
    type Error = IamError;
    const NAME: &'static str = "ValidateAccessQuery";
}

/// Handles [`ValidateAccessQuery`].
///
/// A valid check always gets a decision, an internal failure included: it is the deny
/// `unavailable`. The one error is the caller's mistake of asking for a policy version that IAM has
/// not issued yet, because the versions are only ever issued by IAM; the gateway's decision
/// service waits for such a version instead.
#[derive(Debug)]
pub struct ValidateAccessQueryHandler {
    decisions: Arc<AccessDecisionService>,
    epochs: Arc<dyn PolicyEpochRepository>,
}

impl ValidateAccessQueryHandler {
    /// A handler over the decision path and the policy epoch.
    #[must_use]
    pub const fn new(
        decisions: Arc<AccessDecisionService>,
        epochs: Arc<dyn PolicyEpochRepository>,
    ) -> Self {
        Self { decisions, epochs }
    }

    async fn validate(&self, query: &ValidateAccessQuery) -> Result<DecisionOutcome, IamError> {
        if let Some(minimum) = query.check.min_policy_version() {
            match self.epochs.current().await {
                Ok(epoch) if minimum > epoch.version() => {
                    return Err(IamError::invalid_property(
                        "minPolicyVersion",
                        "This value must not be greater than the current policy version.",
                        "range",
                    ));
                }
                Ok(_current) => {}
                Err(_unavailable) => return Ok(self.decisions.unavailable()),
            }
        }
        Ok(self.decisions.decide(&query.credential, &query.check).await)
    }
}

#[async_trait::async_trait]
impl QueryHandler<ValidateAccessQuery> for ValidateAccessQueryHandler {
    async fn handle(&self, query: ValidateAccessQuery) -> Result<DecisionOutcome, IamError> {
        self.validate(&query).await
    }
}

#[cfg(test)]
mod tests;
