//! Deterministic stand-ins for the codec and the digest ports, for the tests of this module.

use std::hash::{DefaultHasher, Hash as _, Hasher as _};

use crate::error::InvalidStateRecord;
use crate::port::policy_digest::PolicyDigest;
use crate::port::state_record_codec::StateRecordCodec;
use crate::state::key::{ChunkId, StateKey};
use crate::state::model::{CatalogueEntryState, PolicyState};
use crate::value_object::policy_digest_value::PolicyDigestValue;

/// Writes a short text that names every field the tests vary.
#[derive(Debug, Default)]
pub(crate) struct TextCodec;

impl StateRecordCodec for TextCodec {
    fn encode(&self, state: &PolicyState) -> Result<String, InvalidStateRecord> {
        Ok(match state {
            PolicyState::Role(role) => {
                format!(
                    "role {} v{} {:?}",
                    role.name,
                    role.version.value(),
                    role.grants
                )
            }
            PolicyState::Subject(subject) => format!("subject {:?}", subject.assignments),
            PolicyState::Manifest(manifest) => {
                format!("manifest {} {:?}", manifest.catalog_epoch, manifest.chunks)
            }
            PolicyState::Chunk(chunk) => format!("chunk {:?}", chunk.entries),
            PolicyState::Upstream(upstream) => format!(
                "upstream {} v{}",
                upstream.settings.catalog_service(),
                upstream.version.value()
            ),
            PolicyState::Route(route) => format!(
                "route {} v{}",
                route.fields.path_pattern().as_str(),
                route.version.value()
            ),
            PolicyState::RatePolicy(policy) => format!(
                "ratepolicy {} v{}",
                policy.fields.name(),
                policy.version.value()
            ),
            PolicyState::SessionRevocation(state) => format!("revoked session {}", state.session),
            PolicyState::UserRevocation(state) => {
                format!("user cutoff {}", state.tokens_valid_after_micros)
            }
            PolicyState::GlobalRevocation(state) => {
                format!("global cutoff {}", state.tokens_valid_after_micros)
            }
            PolicyState::Head(head) => {
                format!("head {} {:?}", head.version.value(), head.digest.as_bytes())
            }
        })
    }

    fn decode(&self, _key: &StateKey, _payload: &str) -> Result<PolicyState, InvalidStateRecord> {
        Err(InvalidStateRecord::Encoding)
    }

    fn entry_size(&self, entry: &CatalogueEntryState) -> usize {
        entry.key.len()
    }
}

/// Hashes with the standard hasher, which is deterministic for a fixed key.
#[derive(Debug, Default)]
pub(crate) struct HashDigest;

impl HashDigest {
    fn bytes(text: &str) -> [u8; 16] {
        let mut low = DefaultHasher::new();
        text.hash(&mut low);
        let mut high = DefaultHasher::new();
        (text, 1_u8).hash(&mut high);
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&low.finish().to_be_bytes());
        bytes[8..].copy_from_slice(&high.finish().to_be_bytes());
        bytes
    }
}

impl PolicyDigest for HashDigest {
    fn entity_hash(&self, key: &StateKey, canonical: &str) -> PolicyDigestValue {
        PolicyDigestValue::new(&Self::bytes(&format!("{key}|{canonical}"))).unwrap()
    }

    fn content_id(&self, canonical: &str) -> ChunkId {
        ChunkId::from_digest(PolicyDigestValue::from_bytes(Self::bytes(canonical)))
    }
}
