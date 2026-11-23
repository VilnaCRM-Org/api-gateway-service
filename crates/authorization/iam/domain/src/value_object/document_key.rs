//! The cache key of an analysed GraphQL document.

use std::hash::{DefaultHasher, Hash as _, Hasher as _};

use crate::value_object::policy_version::PolicyVersion;

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
        let high = Self::half(0, document, operation_name, catalogue_version);
        let low = Self::half(1, document, operation_name, catalogue_version);
        Self((u128::from(high) << 64) | u128::from(low))
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
        document: &str,
        operation_name: Option<&str>,
        catalogue_version: PolicyVersion,
    ) -> u64 {
        let mut hasher = DefaultHasher::new();
        seed.hash(&mut hasher);
        document.hash(&mut hasher);
        operation_name.hash(&mut hasher);
        catalogue_version.value().hash(&mut hasher);
        hasher.finish()
    }
}

#[cfg(test)]
mod tests;
