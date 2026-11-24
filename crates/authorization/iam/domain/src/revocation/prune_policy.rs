//! When a revocation record may be pruned, and the margin of the cut-offs that IAM computes.

use std::time::{Duration, SystemTime};

/// The margin that a cut-off computed by IAM adds to its commit time, so that a token issued in the
/// same second as the revocation is refused too.
pub const CUTOFF_MARGIN: Duration = Duration::from_secs(2);

/// Twice the largest allowed `JWT_CLOCK_SKEW` (60 seconds): the skew allowance of a record.
pub const SKEW_ALLOWANCE: Duration = Duration::from_secs(120);

/// The safety margin added after the skew allowance.
pub const PRUNE_MARGIN: Duration = Duration::from_secs(60);

/// The rule for the prune-after instant of a revocation record.
///
/// The instant is the later of the revocation time and the cut-off instant of the record, plus the
/// longest `MAX_TOKEN_LIFETIME` ever configured, plus [`SKEW_ALLOWANCE`], plus [`PRUNE_MARGIN`].
/// A token that the record still has to refuse cannot outlive that instant, so the record is kept
/// at least as long as such a token can be presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrunePolicy {
    longest_lifetime: Duration,
}

impl PrunePolicy {
    /// The rule for the longest `MAX_TOKEN_LIFETIME` ever configured.
    #[must_use]
    pub const fn new(longest_lifetime: Duration) -> Self {
        Self { longest_lifetime }
    }

    /// The longest `MAX_TOKEN_LIFETIME` that the rule uses.
    #[must_use]
    pub const fn longest_lifetime(&self) -> Duration {
        self.longest_lifetime
    }

    /// The prune-after instant of a record revoked at `revoked_at` whose cut-off instant is
    /// `cutoff`; a record without a cut-off instant (a session revocation by an operator) passes
    /// `None`. `None` is returned when the instant cannot be represented.
    #[must_use]
    pub fn prune_after(
        &self,
        revoked_at: SystemTime,
        cutoff: Option<SystemTime>,
    ) -> Option<SystemTime> {
        let base = cutoff.map_or(revoked_at, |instant| instant.max(revoked_at));
        base.checked_add(self.longest_lifetime)?
            .checked_add(SKEW_ALLOWANCE)?
            .checked_add(PRUNE_MARGIN)
    }

    /// The cut-off instant that IAM computes at `committed_at`: the commit time plus
    /// [`CUTOFF_MARGIN`].
    #[must_use]
    pub fn cutoff_at(committed_at: SystemTime) -> Option<SystemTime> {
        committed_at.checked_add(CUTOFF_MARGIN)
    }
}

#[cfg(test)]
mod tests;
