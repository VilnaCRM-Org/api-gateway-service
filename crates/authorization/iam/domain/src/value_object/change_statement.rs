//! The statements and guards that a change runs inside its transaction.

use crate::role::statement::RoleStatement;
use crate::user_role::statement::UserRoleStatement;
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
    /// Insert a new role, or update a stored role at the expected version; a duplicate name or id
    /// refuses the change as a duplicate and a stale or deleted stored role as a conflict.
    SaveRole(Box<RoleStatement>),
    /// Insert a new assignment, or update a stored assignment at the expected version.
    ///
    /// A duplicate id, or an assignment that is not revoked with the same subject, role and scope,
    /// refuses the change as a duplicate; a stale or revoked stored assignment refuses it as a
    /// conflict.
    SaveUserRole(Box<UserRoleStatement>),
}

impl ChangeStatement {
    /// Whether the statement holds under `locked`, the policy version that the transaction locked
    /// before any increment. An aggregate write holds here: the storage checks it when it runs.
    #[must_use]
    pub fn holds(&self, locked: PolicyVersion) -> bool {
        match self {
            Self::ExpectPolicyVersion(expected) => *expected == locked,
            Self::SaveRole(_) | Self::SaveUserRole(_) => true,
        }
    }
}

#[cfg(test)]
mod tests;
