//! SHA-256 implementation of the policy digest port.

use iam_domain::{ChunkId, PolicyDigest, PolicyDigestValue, StateKey};
use sha2::{Digest as _, Sha256};

/// Hashes entities and chunks with SHA-256, truncated to the first 16 bytes.
///
/// The hashes depend on their input alone, so every pod and every release computes the same digest
/// for the same policy state.
#[derive(Debug, Default, Clone, Copy)]
pub struct Sha256PolicyDigest;

/// The first 16 bytes of a SHA-256 hash.
fn truncated(hash: &[u8]) -> PolicyDigestValue {
    PolicyDigestValue::from_bytes(std::array::from_fn(|index| {
        hash.get(index).copied().unwrap_or_default()
    }))
}

impl PolicyDigest for Sha256PolicyDigest {
    fn entity_hash(&self, key: &StateKey, canonical: &str) -> PolicyDigestValue {
        let hash: [u8; 32] = Sha256::new()
            .chain_update(key.to_string().as_bytes())
            .chain_update(canonical.as_bytes())
            .finalize()
            .into();
        truncated(&hash)
    }

    fn content_id(&self, canonical: &str) -> ChunkId {
        let hash: [u8; 32] = Sha256::digest(canonical.as_bytes()).into();
        ChunkId::from_digest(truncated(&hash))
    }
}

#[cfg(test)]
mod tests;
