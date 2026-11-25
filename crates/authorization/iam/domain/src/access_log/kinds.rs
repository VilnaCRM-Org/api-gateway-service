//! The lane, the class and the decision kind of an access record.

use crate::value_object::decision::Decision;
use crate::value_object::decision_reason::DecisionReason;

/// Where a record is written (FR-50): each record goes to exactly one lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessLane {
    /// The ordinary lane: sampled allows, errors and aggregates, best effort.
    Access,
    /// The audit lane: denials, always-audit and sensitive decisions and wildcard allows.
    Audit,
}

impl AccessLane {
    /// The value of the `lane` label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Audit => "audit",
        }
    }
}

/// The class that a record counts against: budgets and drops are kept per class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessClass {
    /// A sampled allow: bounded by the sample rate, not by a budget.
    Allow,
    /// A decision or a response that is an error of the gateway or of the upstream.
    Error,
    /// A record of the audit lane.
    Audit,
}

impl AccessClass {
    /// The value of the `class` of a metric event and of a budget name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Error => "error",
            Self::Audit => "audit",
        }
    }
}

/// The value of the `decision` label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessDecision {
    /// The request was allowed and handed to its upstream.
    Allow,
    /// The request was refused.
    Deny,
    /// The gateway could not decide or the request failed with a 5xx.
    Error,
}

impl AccessDecision {
    /// The kind of a decision with its reason and the status of the answer.
    ///
    /// A decision that could not be made (`unavailable`) and every 5xx answer is an error; any
    /// other deny is a deny; the rest are allows.
    #[must_use]
    pub const fn of(decision: Decision, reason: DecisionReason, status: u16) -> Self {
        if matches!(reason, DecisionReason::Unavailable) || status >= 500 {
            Self::Error
        } else if decision.is_allow() {
            Self::Allow
        } else {
            Self::Deny
        }
    }

    /// The value of the `decision` label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Error => "error",
        }
    }
}

#[cfg(test)]
mod tests;
