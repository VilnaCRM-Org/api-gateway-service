//! Port that writes the full state of an entity in its canonical form and reads it back.

use crate::error::InvalidStateRecord;
use crate::state::key::StateKey;
use crate::state::model::{CatalogueEntryState, PolicyState};

/// Encodes a state as the payload of a state record and decodes it again.
///
/// The encoding is canonical: the same state always encodes to the same bytes, on every pod and in
/// every release of the same schema version, because the entity hash and the digest of the whole
/// policy state are computed over those bytes.
pub trait StateRecordCodec: std::fmt::Debug + Send + Sync {
    /// The canonical text of `state`, which carries its schema version.
    ///
    /// # Errors
    ///
    /// [`InvalidStateRecord::Encoding`] when the state cannot be written.
    fn encode(&self, state: &PolicyState) -> Result<String, InvalidStateRecord>;

    /// The state that `payload` holds, for the entity that `key` names.
    ///
    /// # Errors
    ///
    /// [`InvalidStateRecord::UnsupportedSchema`] for a schema version this release does not read,
    /// and [`InvalidStateRecord::Field`] for a payload that is not the state of the key.
    fn decode(&self, key: &StateKey, payload: &str) -> Result<PolicyState, InvalidStateRecord>;

    /// The number of bytes that `entry` adds to the encoding of a chunk.
    fn entry_size(&self, entry: &CatalogueEntryState) -> usize;
}
