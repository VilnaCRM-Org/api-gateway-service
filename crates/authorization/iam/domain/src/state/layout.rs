//! The layout of the catalogue of one service as a manifest and content-addressed chunks.

use crate::error::InvalidStateRecord;
use crate::port::policy_digest::PolicyDigest;
use crate::port::state_record_codec::StateRecordCodec;
use crate::state::key::StateKey;
use crate::state::model::{CatalogueChunk, CatalogueEntryState, CatalogueManifest, PolicyState};
use crate::value_object::service_name::ServiceName;

/// The largest encoded size of one chunk: 1 MiB, the `max.message.bytes` of the state topic.
pub const MAX_CHUNK_BYTES: usize = 1_048_576;

/// The manifest and the chunks of the active entries of one service.
///
/// A chunk is addressed by the hash of its content, so a chunk whose entries do not change keeps its
/// key from one activation to the next and is not written again; only the manifest, which names the
/// chunks and the catalogue epoch, changes with every activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogueLayout {
    states: Vec<(StateKey, PolicyState)>,
}

impl CatalogueLayout {
    /// The layout of `entries`, in chunks of at most [`MAX_CHUNK_BYTES`]. A service without entry
    /// has no manifest and no chunk.
    ///
    /// # Errors
    ///
    /// [`InvalidStateRecord::EntryTooLarge`] when one entry does not fit a chunk, and the error of
    /// the codec when a chunk cannot be encoded.
    pub fn build(
        service: &ServiceName,
        catalog_epoch: i64,
        entries: Vec<CatalogueEntryState>,
        ports: (&dyn StateRecordCodec, &dyn PolicyDigest),
    ) -> Result<Self, InvalidStateRecord> {
        Self::build_bounded(service, catalog_epoch, entries, ports, MAX_CHUNK_BYTES)
    }

    /// The layout of `entries` in chunks of at most `max_chunk_bytes`.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::build`].
    pub fn build_bounded(
        service: &ServiceName,
        catalog_epoch: i64,
        mut entries: Vec<CatalogueEntryState>,
        ports: (&dyn StateRecordCodec, &dyn PolicyDigest),
        max_chunk_bytes: usize,
    ) -> Result<Self, InvalidStateRecord> {
        if entries.is_empty() {
            return Ok(Self { states: Vec::new() });
        }
        entries.sort();
        let (codec, digest) = ports;
        let empty = codec.encode(&PolicyState::Chunk(CatalogueChunk {
            service: service.clone(),
            entries: Vec::new(),
        }))?;
        let limit = max_chunk_bytes.saturating_sub(empty.len());
        let mut states = Vec::new();
        let mut chunks = Vec::new();
        for group in split(entries, limit, codec)? {
            let state = PolicyState::Chunk(CatalogueChunk {
                service: service.clone(),
                entries: group,
            });
            let id = digest.content_id(&codec.encode(&state)?);
            states.push((StateKey::chunk(service.clone(), id.clone()), state));
            chunks.push(id);
        }
        states.insert(
            0,
            (
                StateKey::CatalogueManifest(service.clone()),
                PolicyState::Manifest(CatalogueManifest {
                    service: service.clone(),
                    catalog_epoch,
                    chunks,
                }),
            ),
        );
        Ok(Self { states })
    }

    /// The manifest first, then the chunks in the order of their entries.
    #[must_use]
    pub fn states(&self) -> &[(StateKey, PolicyState)] {
        &self.states
    }
}

/// Splits sorted entries into groups whose encoded entries add up to at most `limit` bytes.
fn split(
    entries: Vec<CatalogueEntryState>,
    limit: usize,
    codec: &dyn StateRecordCodec,
) -> Result<Vec<Vec<CatalogueEntryState>>, InvalidStateRecord> {
    let mut groups: Vec<Vec<CatalogueEntryState>> = Vec::new();
    let mut used = 0_usize;
    for entry in entries {
        let size = codec.entry_size(&entry);
        if size > limit {
            return Err(InvalidStateRecord::EntryTooLarge);
        }
        match groups.last_mut() {
            Some(group) if used.saturating_add(size) <= limit => {
                group.push(entry);
                used = used.saturating_add(size);
            }
            _ => {
                groups.push(vec![entry]);
                used = size;
            }
        }
    }
    Ok(groups)
}

#[cfg(test)]
mod tests;
