//! Port that digests the canonical request of an idempotent write.

use crate::value_object::request_digest::RequestDigest;

/// Digests the canonical text of a write request, so that a replay with the same idempotency key
/// can be told from a different request that reuses the key.
///
/// The digest is a one-way function of the text and nothing else: equal texts give equal digests
/// on every pod and in every release, because a replay may land on another pod within 24 hours.
pub trait RequestDigester: std::fmt::Debug + Send + Sync {
    /// The SHA-256 digest of the UTF-8 bytes of `canonical`.
    fn digest(&self, canonical: &str) -> RequestDigest;
}
