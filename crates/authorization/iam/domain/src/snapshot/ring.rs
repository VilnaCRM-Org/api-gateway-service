//! The ring of the `iam-digest-after` values of the last applied versions.

use std::collections::VecDeque;

use crate::value_object::policy_digest_value::PolicyDigestValue;
use crate::value_object::policy_version::PolicyVersion;

/// The number of versions whose digest the ring keeps.
pub const DIGEST_RING_CAPACITY: usize = 100_000;

/// The digests that the last [`DIGEST_RING_CAPACITY`] applied versions ended with. Versions are
/// recorded in increasing order, so a lookup is an offset from the newest one.
#[derive(Debug, Clone)]
pub struct DigestRing {
    capacity: usize,
    newest: Option<PolicyVersion>,
    digests: VecDeque<PolicyDigestValue>,
}

impl Default for DigestRing {
    fn default() -> Self {
        Self::with_capacity(DIGEST_RING_CAPACITY)
    }
}

impl DigestRing {
    /// A ring that keeps the last `capacity` versions (at least one).
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            newest: None,
            digests: VecDeque::new(),
        }
    }

    /// Records the digest of `version`. A version that is not newer than the newest recorded one
    /// is not recorded.
    pub fn record(&mut self, version: PolicyVersion, digest: PolicyDigestValue) {
        if self.newest.is_some_and(|newest| version <= newest) {
            return;
        }
        let gap = self.newest.map_or(1, |newest| {
            usize::try_from(version.value().saturating_sub(newest.value())).unwrap_or(usize::MAX)
        });
        if gap > 1 {
            // A rebuild jumps over versions: the older digests no longer line up.
            self.digests.clear();
        }
        self.digests.push_back(digest);
        while self.digests.len() > self.capacity {
            self.digests.pop_front();
        }
        self.newest = Some(version);
    }

    /// The digest that `version` ended with, when the ring still holds it.
    #[must_use]
    pub fn get(&self, version: PolicyVersion) -> Option<PolicyDigestValue> {
        let newest = self.newest?;
        let back = usize::try_from(newest.value().checked_sub(version.value())?).ok()?;
        let index = self.digests.len().checked_sub(1)?.checked_sub(back)?;
        self.digests.get(index).copied()
    }

    /// The newest version recorded.
    #[must_use]
    pub const fn newest(&self) -> Option<PolicyVersion> {
        self.newest
    }

    /// The number of versions held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.digests.len()
    }

    /// Whether no version is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.digests.is_empty()
    }
}

#[cfg(test)]
mod tests;
