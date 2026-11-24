//! The check of the derived structures against the raw records (FR-74).
//!
//! The structures that decisions read (the compiled role sets, the interned assignment lists, the
//! role-to-subject reverse index and the routers) are kept up to date incrementally. A bug in that
//! maintenance would make the gateway decide on a wrong snapshot, so the pod rebuilds them from the
//! raw records, one rotating group of shards at a time, and compares what it rebuilt with what it
//! holds.

use crate::value_object::policy_digest_value::PolicyDigestValue;

/// The number of groups the shards are rotated through: one check covers one group, a sixteenth of
/// the shards, so that 16 checks cover every shard once.
pub const CHECK_GROUPS: usize = 16;

/// Whether `shard` belongs to `group` of the rotation.
#[must_use]
pub fn in_group(shard: usize, group: usize) -> bool {
    shard.checked_rem(CHECK_GROUPS) == Some(group)
}

/// A derived structure that differs from the one the raw records give.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the derived structures of shard {shard} do not match the raw records")]
pub struct DerivedMismatch {
    /// The shard whose structures differ.
    pub shard: usize,
    /// The hash of the decision-relevant output rebuilt from the raw records.
    pub rebuilt: PolicyDigestValue,
    /// The hash of the same output read from the incremental structures.
    pub held: PolicyDigestValue,
}

/// Rebuilds the derived structures of one group of shards and compares them with the held ones.
pub trait DerivedStateAudit {
    /// Checks the shards of `group` (`0..CHECK_GROUPS`) and returns how many it checked.
    ///
    /// # Errors
    ///
    /// Returns the first shard whose rebuilt output differs from the held one.
    fn audit_group(&mut self, group: usize) -> Result<usize, DerivedMismatch>;
}

#[cfg(test)]
mod tests;
