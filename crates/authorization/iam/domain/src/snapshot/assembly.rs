//! `VersionAssembly`: collects the records of one policy version by `iam-seq`, drops duplicates and
//! reports whether the version is complete.

use std::collections::BTreeMap;

use crate::state::key::StateKey;
use crate::value_object::log_epoch::LogEpoch;
use crate::value_object::policy_digest_value::PolicyDigestValue;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::relay_epoch::RelayEpoch;

/// One record of the policy state topic with the framing of its headers: the version, the
/// sequence and the count of its transaction, the digest after it and the two epochs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedRecord {
    /// The state key.
    pub key: StateKey,
    /// The canonical state, or `None` for a tombstone.
    pub payload: Option<String>,
    /// The policy version (`iam-version`).
    pub version: PolicyVersion,
    /// The position within the version, from 1 (`iam-seq`).
    pub seq: u32,
    /// The number of records of the version, the head included (`iam-count`).
    pub count: u32,
    /// The digest of the policy state after this record (`iam-digest-after`).
    pub digest_after: PolicyDigestValue,
    /// The epoch of the policy log (`iam-log-epoch`).
    pub log_epoch: LogEpoch,
    /// The epoch of the relay that sent the record (`iam-relay-epoch`).
    pub relay_epoch: RelayEpoch,
}

/// What offering one record to an assembly did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    /// The record is new for its position.
    Added,
    /// The same record was already there, as a relay takeover sends it again: dropped.
    Duplicate,
    /// A record of the same position with other content: the log is not trustworthy.
    Conflicting,
    /// The record belongs to another version than the one assembled, or its framing is invalid.
    Foreign,
}

/// Whether every record of the version is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completeness {
    /// All `count` records are present.
    Complete,
    /// Records are still missing.
    Incomplete {
        /// How many records are missing, or `None` while the count is not known.
        missing: Option<u32>,
    },
}

/// The records of one version, collected in any order.
#[derive(Debug, Clone)]
pub struct VersionAssembly {
    version: PolicyVersion,
    count: Option<u32>,
    records: BTreeMap<u32, VersionedRecord>,
}

impl VersionAssembly {
    /// An empty assembly of `version`.
    #[must_use]
    pub const fn new(version: PolicyVersion) -> Self {
        Self {
            version,
            count: None,
            records: BTreeMap::new(),
        }
    }

    /// The version assembled.
    #[must_use]
    pub const fn version(&self) -> PolicyVersion {
        self.version
    }

    /// Offers one record.
    pub fn offer(&mut self, record: VersionedRecord) -> Offer {
        let framed = record.seq >= 1 && record.seq <= record.count;
        let consistent = self.count.is_none_or(|count| count == record.count);
        if record.version != self.version || !framed || !consistent {
            return Offer::Foreign;
        }
        self.count = Some(record.count);
        match self.records.get(&record.seq) {
            None => {
                self.records.insert(record.seq, record);
                Offer::Added
            }
            Some(known) if same_content(known, &record) => Offer::Duplicate,
            Some(_) => Offer::Conflicting,
        }
    }

    /// Whether all records are present.
    #[must_use]
    pub fn completeness(&self) -> Completeness {
        let held = u32::try_from(self.records.len()).unwrap_or(u32::MAX);
        match self.count {
            Some(count) if held >= count => Completeness::Complete,
            Some(count) => Completeness::Incomplete {
                missing: Some(count.saturating_sub(held)),
            },
            None => Completeness::Incomplete { missing: None },
        }
    }

    /// The records in `iam-seq` order, the head last.
    #[must_use]
    pub fn records(&self) -> Vec<&VersionedRecord> {
        self.records.values().collect()
    }

    /// The last record of the version: the one that carries the digest the version ends with.
    #[must_use]
    pub fn last(&self) -> Option<&VersionedRecord> {
        self.records.values().next_back()
    }

    /// The epochs of the highest relay that sent a record of this version.
    #[must_use]
    pub fn relay_epoch(&self) -> Option<RelayEpoch> {
        self.records.values().map(|record| record.relay_epoch).max()
    }

    /// The log epoch of the records, which is the highest one seen.
    #[must_use]
    pub fn log_epoch(&self) -> Option<LogEpoch> {
        self.records.values().map(|record| record.log_epoch).max()
    }
}

/// Whether two records of the same position carry the same content. The relay epoch is not part
/// of the content: a takeover sends the same record again under a higher relay epoch.
fn same_content(known: &VersionedRecord, other: &VersionedRecord) -> bool {
    known.key == other.key
        && known.payload == other.payload
        && known.digest_after == other.digest_after
        && known.log_epoch == other.log_epoch
}

#[cfg(test)]
mod tests;
