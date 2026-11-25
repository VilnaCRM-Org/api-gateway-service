//! The cache key of an analysed GraphQL document.

use std::hash::{DefaultHasher, Hash as _, Hasher as _};

use crate::value_object::log_epoch::LogEpoch;
use crate::value_object::policy_digest_value::PolicyDigestValue;
use crate::value_object::policy_epoch::PolicyEpoch;
use crate::value_object::policy_version::PolicyVersion;

/// What besides the version tells two catalogues of one version apart: the epoch of the log and
/// the digest of the state.
type Stamp = Option<(LogEpoch, PolicyDigestValue)>;

/// A 128-bit hash of the document, the operation name and the catalogue version.
///
/// A hash can collide, so a cache hit counts only when the keys are equal and the stored document
/// equals the requested one in full: see [`DocumentKey::confirms`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DocumentKey(u128);

impl DocumentKey {
    /// The key of `document` analysed for `operation_name` under `catalogue_version`.
    #[must_use]
    pub fn of(
        document: &str,
        operation_name: Option<&str>,
        catalogue_version: PolicyVersion,
    ) -> Self {
        Self::stamped(document, operation_name, catalogue_version, None)
    }

    /// The key of `document` analysed for `operation_name` under the catalogue read at `epoch`.
    ///
    /// The version alone is not enough: after a resync to a new log epoch a version can come back
    /// with other content, so the log epoch and the digest of the state are part of the key.
    #[must_use]
    pub fn in_epoch(document: &str, operation_name: Option<&str>, epoch: &PolicyEpoch) -> Self {
        Self::stamped(
            document,
            operation_name,
            epoch.version(),
            Some((epoch.log_epoch(), epoch.digest())),
        )
    }

    fn stamped(
        document: &str,
        operation_name: Option<&str>,
        catalogue_version: PolicyVersion,
        stamp: Stamp,
    ) -> Self {
        let half = |seed| Self::half(seed, (document, operation_name), catalogue_version, stamp);
        Self((u128::from(half(0)) << 64) | u128::from(half(1)))
    }

    /// A key with a given digest; a test hook that forces two documents to one hash.
    #[must_use]
    pub const fn from_digest(digest: u128) -> Self {
        Self(digest)
    }

    /// The 128-bit digest.
    #[must_use]
    pub const fn digest(self) -> u128 {
        self.0
    }

    /// Whether a lookup with this key and `document` hits the entry stored under `stored_key`
    /// for `stored_document`: both the keys and the full texts must be equal.
    #[must_use]
    pub fn confirms(self, stored_key: Self, stored_document: &str, document: &str) -> bool {
        self == stored_key && stored_document == document
    }

    fn half(
        seed: u8,
        (document, operation_name): (&str, Option<&str>),
        catalogue_version: PolicyVersion,
        stamp: Stamp,
    ) -> u64 {
        let mut hasher = DefaultHasher::new();
        seed.hash(&mut hasher);
        document.hash(&mut hasher);
        operation_name.hash(&mut hasher);
        catalogue_version.value().hash(&mut hasher);
        stamp.hash(&mut hasher);
        hasher.finish()
    }
}

#[cfg(test)]
mod tests;
