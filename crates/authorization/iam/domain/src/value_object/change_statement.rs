//! The statements and guards that a change runs inside its transaction.

use crate::value_object::policy_version::PolicyVersion;

/// One aggregate statement or guard of a change, described for the unit of work to execute.
///
/// The unit of work runs it inside the transaction, after it has locked the policy version and
/// before it writes the outbox, the audit record, the change receipt and the idempotency record.
///
/// The aggregate stories add one variant per aggregate write (an insert, or an update with
/// `WHERE version = $expected`); a failing statement rolls the whole change back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeStatement {
    /// Refuse the change with a conflict when the policy version locked by the transaction differs
    /// from the version the change was decided against.
    ExpectPolicyVersion(PolicyVersion),
}

impl ChangeStatement {
    /// Whether the statement holds under `locked`, the policy version that the transaction locked
    /// before any increment.
    #[must_use]
    pub fn holds(&self, locked: PolicyVersion) -> bool {
        match self {
            Self::ExpectPolicyVersion(expected) => *expected == locked,
        }
    }
}

#[cfg(test)]
mod tests;
