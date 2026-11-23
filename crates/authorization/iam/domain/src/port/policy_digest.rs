//! Port that hashes entities and chunks for the digest of the policy state.

use crate::state::key::{ChunkId, StateKey};
use crate::value_object::policy_digest_value::PolicyDigestValue;

/// Hashes the canonical state of an entity.
///
/// The hash is a one-way function of its input and nothing else: equal inputs give equal hashes
/// on every pod and in every release.
pub trait PolicyDigest: std::fmt::Debug + Send + Sync {
    /// The hash of an entity: the first 16 bytes of the SHA-256 of the printed key followed by the
    /// canonical state.
    fn entity_hash(&self, key: &StateKey, canonical: &str) -> PolicyDigestValue;

    /// The content address of a catalogue chunk whose canonical text is `canonical`.
    fn content_id(&self, canonical: &str) -> ChunkId;
}
