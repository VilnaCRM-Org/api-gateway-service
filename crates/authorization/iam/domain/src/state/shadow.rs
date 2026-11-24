//! The shadow bootstrap: the policy state rebuilt from the records of the state topic, as a pod
//! that bootstraps from the topic would rebuild it (FR-77).
//!
//! The rules are those of the topic: of the records of a key the one with the highest version
//! wins, a tombstone deletes the key, and a record whose relay epoch is lower than an epoch that
//! the log already showed is the late append of a zombie relay and is ignored. The digest is the
//! combination of the entity hashes of the keys that remain; it must equal the digest that the
//! newest `__head` carries.

use std::collections::BTreeMap;

use crate::error::InvalidStateRecord;
use crate::port::policy_digest::PolicyDigest;
use crate::port::policy_log_tail::TailRecord;
use crate::port::state_record_codec::StateRecordCodec;
use crate::state::key::StateKey;
use crate::state::model::{PolicyHead, PolicyState};
use crate::value_object::policy_digest_value::PolicyDigestValue;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::relay_epoch::RelayEpoch;

/// What the rebuilt state says about the topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowVerdict {
    /// The topic holds no record that counts.
    Empty,
    /// A key holds a version above the newest `__head`, or the topic holds records but no head:
    /// the relay is in the middle of a version.
    Incomplete,
    /// The rebuilt digest equals the digest of the newest `__head`.
    Consistent(PolicyHead),
    /// The rebuilt digest differs from the digest of the newest `__head`.
    Corrupt {
        /// The newest head.
        head: PolicyHead,
        /// The digest that the records rebuild.
        computed: PolicyDigestValue,
    },
}

/// The latest record of a key: its version and, unless it is a tombstone, the hash of its value.
#[derive(Debug, Clone, Copy)]
struct Entity {
    version: PolicyVersion,
    hash: Option<PolicyDigestValue>,
}

/// The state rebuilt from the records that were [applied](Self::apply) in offset order.
#[derive(Debug)]
pub struct ShadowState {
    newest_epoch: RelayEpoch,
    entities: BTreeMap<String, Entity>,
    head: Option<PolicyHead>,
    ignored: u64,
}

impl Default for ShadowState {
    fn default() -> Self {
        Self::new()
    }
}

impl ShadowState {
    /// An empty state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            newest_epoch: RelayEpoch::ZERO,
            entities: BTreeMap::new(),
            head: None,
            ignored: 0,
        }
    }

    /// Applies the next record of the topic.
    ///
    /// # Errors
    ///
    /// [`InvalidStateRecord::Key`] for a key that is not a key of the topic and
    /// [`InvalidStateRecord::Encoding`] for a `__head` without a value or with the value of another
    /// entity; the error of the codec for a head it cannot read.
    pub fn apply(
        &mut self,
        record: &TailRecord,
        ports: (&dyn StateRecordCodec, &dyn PolicyDigest),
    ) -> Result<(), InvalidStateRecord> {
        if record.relay_epoch < self.newest_epoch {
            self.ignored = self.ignored.saturating_add(1);
            return Ok(());
        }
        self.newest_epoch = record.relay_epoch;
        let key = StateKey::parse(&record.key)?;
        if key == StateKey::Head {
            return self.apply_head(record, ports.0);
        }
        self.apply_entity(&key, record, ports.1);
        Ok(())
    }

    fn apply_head(
        &mut self,
        record: &TailRecord,
        codec: &dyn StateRecordCodec,
    ) -> Result<(), InvalidStateRecord> {
        let payload = record
            .payload
            .as_deref()
            .ok_or(InvalidStateRecord::Encoding)?;
        let PolicyState::Head(head) = codec.decode(&StateKey::Head, payload)? else {
            return Err(InvalidStateRecord::Encoding);
        };
        if self
            .head
            .is_none_or(|current| head.version >= current.version)
        {
            self.head = Some(head);
        }
        Ok(())
    }

    fn apply_entity(&mut self, key: &StateKey, record: &TailRecord, digest: &dyn PolicyDigest) {
        let newer = self
            .entities
            .get(&record.key)
            .is_none_or(|current| record.version >= current.version);
        if newer {
            let hash = record
                .payload
                .as_deref()
                .map(|canonical| digest.entity_hash(key, canonical));
            self.entities.insert(
                record.key.clone(),
                Entity {
                    version: record.version,
                    hash,
                },
            );
        }
    }

    /// How many records the epoch rule ignored.
    #[must_use]
    pub const fn ignored(&self) -> u64 {
        self.ignored
    }

    /// The digest of the keys that remain.
    #[must_use]
    pub fn computed_digest(&self) -> PolicyDigestValue {
        self.entities
            .values()
            .filter_map(|entity| entity.hash)
            .fold(PolicyDigestValue::ZERO, PolicyDigestValue::combined)
    }

    /// What the applied records say about the topic.
    #[must_use]
    pub fn verdict(&self) -> ShadowVerdict {
        let Some(head) = self.head else {
            return if self.entities.is_empty() {
                ShadowVerdict::Empty
            } else {
                ShadowVerdict::Incomplete
            };
        };
        if self
            .entities
            .values()
            .any(|entity| entity.version > head.version)
        {
            return ShadowVerdict::Incomplete;
        }
        let computed = self.computed_digest();
        if computed == head.digest {
            ShadowVerdict::Consistent(head)
        } else {
            ShadowVerdict::Corrupt { head, computed }
        }
    }
}

#[cfg(test)]
mod tests;
