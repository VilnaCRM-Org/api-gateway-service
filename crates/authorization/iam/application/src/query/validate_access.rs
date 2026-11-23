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
        match check_minimum(self.epochs.as_ref(), &query.check).await {
            MinimumVersion::Held => {
                Ok(self.decisions.decide(&query.credential, &query.check).await)
            }
            MinimumVersion::Unissued => Err(IamError::invalid_property(
                "minPolicyVersion",
                "This value must not be greater than the current policy version.",
                "range",
            )),
            MinimumVersion::Unreadable => Ok(self.decisions.unavailable()),
        }
    }
}

/// What the policy epoch says about the policy version that a check must reflect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MinimumVersion {
    /// The check names no version, or IAM has issued it.
    Held,
    /// The check names a version that IAM has not issued yet.
    Unissued,
    /// The epoch cannot be read, so the check cannot be decided on fresh policy.
    Unreadable,
}

/// Compares the policy version that `check` must reflect with the current one.
pub(crate) async fn check_minimum(
    epochs: &dyn PolicyEpochRepository,
    check: &AccessCheck,
) -> MinimumVersion {
    let Some(minimum) = check.min_policy_version() else {
        return MinimumVersion::Held;
    };
    match epochs.current().await {
        Ok(epoch) if minimum > epoch.version() => MinimumVersion::Unissued,
        Ok(_current) => MinimumVersion::Held,
        Err(_unavailable) => MinimumVersion::Unreadable,
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
