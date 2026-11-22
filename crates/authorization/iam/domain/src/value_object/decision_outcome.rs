//! The result of an access check: the verdict of the rule and the facts of the response.

use crate::value_object::decision::Decision;
use crate::value_object::decision_reason::DecisionReason;
use crate::value_object::identifier::DecisionId;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::scope_set::ScopeSet;
use crate::value_object::subject::SubjectRef;

/// What the decision rule concluded: the reason, the denied keys and the scopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionVerdict {
    reason: DecisionReason,
    denied: Vec<String>,
    scopes: ScopeSet,
}

impl DecisionVerdict {
    /// An allow with the projects in which every required key is held.
    #[must_use]
    pub const fn allow(scopes: ScopeSet) -> Self {
        Self {
            reason: DecisionReason::Allowed,
            denied: Vec::new(),
            scopes,
        }
    }

    /// A deny with its reason and the denied keys or coordinates. A deny never carries scopes,
    /// and `allowed` is never a deny reason: it is reported as `unavailable`.
    #[must_use]
    pub const fn deny(reason: DecisionReason, denied: Vec<String>) -> Self {
        let reason = if matches!(reason, DecisionReason::Allowed) {
            DecisionReason::Unavailable
        } else {
            reason
        };
        Self {
            reason,
            denied,
            scopes: ScopeSet::empty(),
        }
    }

    /// Allow or deny, derived from the reason.
    #[must_use]
    pub const fn decision(&self) -> Decision {
        self.reason.decision()
    }

    /// The reason code.
    #[must_use]
    pub const fn reason(&self) -> DecisionReason {
        self.reason
    }

    /// The denied keys or coordinates; empty for an allow.
    #[must_use]
    pub fn denied(&self) -> &[String] {
        &self.denied
    }

    /// The projects in which the check is allowed; empty for a deny.
    #[must_use]
    pub const fn scopes(&self) -> &ScopeSet {
        &self.scopes
    }
}

/// The decision body of FR-6: the verdict, the subject, the decision id and the policy version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionOutcome {
    verdict: DecisionVerdict,
    decision_id: DecisionId,
    subject: Option<SubjectRef>,
    policy_version: Option<PolicyVersion>,
}

impl DecisionOutcome {
    /// Joins the verdict with the facts of the response. The subject is absent when no token
    /// resolved; the policy version is absent when no policy could be read.
    #[must_use]
    pub const fn new(
        verdict: DecisionVerdict,
        decision_id: DecisionId,
        subject: Option<SubjectRef>,
        policy_version: Option<PolicyVersion>,
    ) -> Self {
        Self {
            verdict,
            decision_id,
            subject,
            policy_version,
        }
    }

    /// Allow or deny.
    #[must_use]
    pub const fn decision(&self) -> Decision {
        self.verdict.decision()
    }

    /// The reason code.
    #[must_use]
    pub const fn reason(&self) -> DecisionReason {
        self.verdict.reason()
    }

    /// The denied keys or coordinates.
    #[must_use]
    pub fn denied(&self) -> &[String] {
        self.verdict.denied()
    }

    /// The projects in which the check is allowed.
    #[must_use]
    pub const fn scopes(&self) -> &ScopeSet {
        self.verdict.scopes()
    }

    /// The verdict of the rule.
    #[must_use]
    pub const fn verdict(&self) -> &DecisionVerdict {
        &self.verdict
    }

    /// The id of this decision.
    #[must_use]
    pub const fn decision_id(&self) -> DecisionId {
        self.decision_id
    }

    /// The subject the check was decided for.
    #[must_use]
    pub const fn subject(&self) -> Option<&SubjectRef> {
        self.subject.as_ref()
    }

    /// The policy version the decision reflects.
    #[must_use]
    pub const fn policy_version(&self) -> Option<PolicyVersion> {
        self.policy_version
    }
}

#[cfg(test)]
mod tests;
