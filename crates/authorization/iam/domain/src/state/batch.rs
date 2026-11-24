//! The state rows of one versioned transaction: one row per changed entity, framed with the
//! version, the sequence, the count and the digest after the row, then the head of the version.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::InvalidStateRecord;
use crate::port::policy_digest::PolicyDigest;
use crate::port::state_record_codec::StateRecordCodec;
use crate::state::key::StateKey;
use crate::state::model::{PolicyHead, PolicyState};
use crate::value_object::policy_digest_value::PolicyDigestValue;
use crate::value_object::policy_version::PolicyVersion;

/// One entity of a transaction with its state before and after the transaction: `None` before
/// means that the entity did not exist, `None` after means that it was deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateChange {
    /// The key of the entity.
    pub key: StateKey,
    /// The state before the transaction.
    pub before: Option<PolicyState>,
    /// The state after the transaction.
    pub after: Option<PolicyState>,
}

/// One framed row of a version: a state record, or the head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateRow {
    key: StateKey,
    payload: Option<String>,
    seq: u32,
    count: u32,
    digest_after: PolicyDigestValue,
}

impl StateRow {
    /// The key of the record.
    #[must_use]
    pub const fn key(&self) -> &StateKey {
        &self.key
    }

    /// The canonical state, or `None` for a tombstone.
    #[must_use]
    pub fn payload(&self) -> Option<&str> {
        self.payload.as_deref()
    }

    /// The position of the row in its version, from 1.
    #[must_use]
    pub const fn seq(&self) -> u32 {
        self.seq
    }

    /// The number of rows of the version, the head included.
    #[must_use]
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// The digest of the whole policy state once this row is applied.
    #[must_use]
    pub const fn digest_after(&self) -> PolicyDigestValue {
        self.digest_after
    }
}

/// The state rows of a version and the digest it ends with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateBatch {
    version: PolicyVersion,
    rows: Vec<StateRow>,
    digest: PolicyDigestValue,
}

/// A changed entity whose encoding differs, with the move it makes in the digest.
struct Movement {
    key: StateKey,
    payload: Option<String>,
    delta: PolicyDigestValue,
}

impl StateBatch {
    /// Frames the changes of the transaction that takes the policy to `version`, given the digest
    /// `before` it. The rows follow the order of the keys; an entity whose encoding does not change
    /// writes no row; the head is the last row.
    ///
    /// # Errors
    ///
    /// The error of the codec when a state cannot be encoded.
    pub fn assemble<I: IntoIterator<Item = StateChange>>(
        version: PolicyVersion,
        before: PolicyDigestValue,
        changes: I,
        ports: (&dyn StateRecordCodec, &dyn PolicyDigest),
    ) -> Result<Self, InvalidStateRecord> {
        Self::assemble_republishing(version, before, changes, &BTreeSet::new(), ports)
    }

    /// Frames the changes like [`Self::assemble`], and writes a row for every key of `republished`
    /// that exists after the transaction even when its encoding did not change: a resync
    /// publishes the unchanged state of each entity again under a new version, and the digest does
    /// not move by it.
    ///
    /// # Errors
    ///
    /// The error of the codec when a state cannot be encoded.
    pub fn assemble_republishing<I: IntoIterator<Item = StateChange>>(
        version: PolicyVersion,
        before: PolicyDigestValue,
        changes: I,
        republished: &BTreeSet<StateKey>,
        ports: (&dyn StateRecordCodec, &dyn PolicyDigest),
    ) -> Result<Self, InvalidStateRecord> {
        let (codec, digest) = ports;
        let by_key: BTreeMap<StateKey, StateChange> = changes
            .into_iter()
            .map(|change| (change.key.clone(), change))
            .collect();
        let movements = by_key
            .values()
            .filter_map(|change| {
                let forced = republished.contains(&change.key);
                movement(change, forced, codec, digest).transpose()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let count = u32::try_from(movements.len())
            .ok()
            .and_then(|rows| rows.checked_add(1))
            .ok_or(InvalidStateRecord::Encoding)?;
        let mut running = before;
        let mut rows = Vec::new();
        for (moved, seq) in movements.into_iter().zip(1_u32..) {
            running = running.combined(moved.delta);
            rows.push(StateRow {
                key: moved.key,
                payload: moved.payload,
                seq,
                count,
                digest_after: running,
            });
        }
        let head = PolicyState::Head(PolicyHead {
            version,
            digest: running,
        });
        rows.push(StateRow {
            key: StateKey::Head,
            payload: Some(codec.encode(&head)?),
            seq: count,
            count,
            digest_after: running,
        });
        Ok(Self {
            version,
            rows,
            digest: running,
        })
    }

    /// The policy version of the rows.
    #[must_use]
    pub const fn version(&self) -> PolicyVersion {
        self.version
    }

    /// The rows in write order; the last one is the head.
    #[must_use]
    pub fn rows(&self) -> &[StateRow] {
        &self.rows
    }

    /// The digest of the whole policy state at the end of the version.
    #[must_use]
    pub const fn digest(&self) -> PolicyDigestValue {
        self.digest
    }
}

/// The move that `change` makes, or `None` when the entity encodes the same before and after and
/// is not `forced` to be written again; a forced entity that does not exist writes nothing.
fn movement(
    change: &StateChange,
    forced: bool,
    codec: &dyn StateRecordCodec,
    digest: &dyn PolicyDigest,
) -> Result<Option<Movement>, InvalidStateRecord> {
    let before = change
        .before
        .as_ref()
        .map(|state| codec.encode(state))
        .transpose()?;
    let after = change
        .after
        .as_ref()
        .map(|state| codec.encode(state))
        .transpose()?;
    if before == after && !(forced && after.is_some()) {
        return Ok(None);
    }
    let hash = |canonical: &Option<String>| {
        canonical
            .as_deref()
            .map_or(PolicyDigestValue::ZERO, |text| {
                digest.entity_hash(&change.key, text)
            })
    };
    Ok(Some(Movement {
        key: change.key.clone(),
        delta: hash(&before).combined(hash(&after)),
        payload: after,
    }))
}

#[cfg(test)]
mod tests;
