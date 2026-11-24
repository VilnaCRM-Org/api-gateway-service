//! The bootstrap of a gateway pod as a pure step function (FR-71, NFR-28, NFR-37).
//!
//! The machine captures the last stable offset `HW0`, reads the state topic from offset 0 up to
//! it and then judges what it holds:
//!
//! - the newest `__head` names the highest complete version `V`, because a head is the last row of
//!   its version;
//! - rows of exactly the version `V + 1` without a head are the version that a relay left half
//!   written or that straddles `HW0`: the machine reads once more up to the stable offset of that
//!   moment, and when the version is still incomplete the pod publishes `V` and reports the
//!   trailing version as incomplete;
//! - a row of any other version above `V` fails closed;
//! - the digest of the state at `V` must equal the digest of the head.
//!
//! A failure asks for one retry from a fresh capture of `HW0`; a second failure ends the machine
//! in "not started". The machine performs no I/O: the [driver](run_bootstrap) executes its actions.

mod run;

use std::collections::BTreeMap;
use std::sync::Arc;

use iam_domain::{
    Completeness, FramedRecord, LogEpoch, Offer, PolicyDigest, PolicyDigestValue, PolicyState,
    PolicyVersion, RelayEpoch, StateKey, StateRecordCodec, TAIL_READ_LIMIT, VersionAssembly,
    VersionedRecord,
};

pub use run::{BootstrapOutcome, run_bootstrap};

/// How many times a failed bootstrap starts again before the pod stays not started.
const RETRIES: u8 = 1;

/// How many of the newest versions keep the offset of their first record.
const KEPT_STARTS: usize = 3;

/// The ports the pure judgement uses; both are deterministic and perform no I/O.
#[derive(Debug, Clone)]
pub struct BootstrapPorts {
    /// Reads the head of a version.
    pub codec: Arc<dyn StateRecordCodec>,
    /// Hashes the entities.
    pub digest: Arc<dyn PolicyDigest>,
}

/// One live key of the state at the published version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapEntry {
    /// The key.
    pub key: StateKey,
    /// The version the key was last changed in.
    pub version: PolicyVersion,
    /// The canonical state.
    pub payload: String,
}

/// The state the pod publishes when the bootstrap succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapSnapshot {
    /// The highest complete version; zero for an empty topic.
    pub version: PolicyVersion,
    /// The log epoch of the head of that version.
    pub log_epoch: LogEpoch,
    /// The digest of the state, equal to the digest of the head.
    pub digest: PolicyDigestValue,
    /// The live keys.
    pub entries: Vec<BootstrapEntry>,
    /// The version after `version` whose rows are on the topic without its head, when there is
    /// one: the relay stopped in the middle of it.
    pub incomplete: Option<PolicyVersion>,
    /// The offset the tail starts from: the first row of the incomplete trailing version, so that
    /// the tail applies it once its remaining rows arrive; the end of the read when there is none.
    pub tail_from: i64,
    /// The offset after the last record the bootstrap read. The tail checks the broker append
    /// time of the records from here on only: older ones are history, not news.
    pub read_to: i64,
}

/// Why a bootstrap attempt failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BootstrapFailure {
    /// A record carries a version above the highest complete head and it is not the one trailing
    /// version of a stopped relay.
    #[error("a record carries version {version}, above the highest complete head")]
    VersionAboveHead {
        /// The version.
        version: i64,
    },
    /// The state at the highest complete version does not hash to the digest of its head.
    #[error("the digest at version {version} is {computed}, the head carries {expected}")]
    DigestMismatch {
        /// The version of the head.
        version: i64,
        /// The digest the head carries, in hexadecimal.
        expected: String,
        /// The digest the records rebuild, in hexadecimal.
        computed: String,
    },
    /// The newest head cannot be read.
    #[error("the head of the state topic cannot be read: {0}")]
    UnreadableHead(String),
    /// The topic could not be read.
    #[error("the state topic cannot be read: {0}")]
    ReadFailed(String),
}

/// What the driver tells the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapInput {
    /// The bootstrap begins.
    Start,
    /// The last stable offset that the capture returned.
    StableEnd(i64),
    /// The records of the last read, in offset order.
    Records(Vec<FramedRecord>),
    /// The last capture or read failed.
    ReadFailed(String),
}

/// What the machine asks the driver to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapAction {
    /// Capture the last stable offset of the topic.
    CaptureStableEnd,
    /// Read the records with `from <= offset < up_to`.
    Read {
        /// The first offset.
        from: i64,
        /// The offset after the last one.
        up_to: i64,
    },
    /// The bootstrap succeeded: publish this state.
    Publish(BootstrapSnapshot),
    /// The attempt failed; the machine starts again, so a capture follows in the same list.
    Retry(BootstrapFailure),
    /// The second attempt failed: the pod stays not started.
    NotStarted(BootstrapFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Capturing { extended: bool },
    Reading { extended: bool, target: i64 },
    Done,
}

/// The two newest records of a key by version: the newest, and the one before it, which is the
/// state at the highest complete version when the newest belongs to a version that is trailing.
#[derive(Debug, Default)]
struct KeyRecords(Vec<VersionedRecord>);

impl KeyRecords {
    fn offer(&mut self, record: VersionedRecord) {
        self.0.retain(|held| held.version != record.version);
        self.0.push(record);
        self.0.sort_by_key(|held| held.version);
        if self.0.len() > 2 {
            self.0.remove(0);
        }
    }

    fn newest(&self) -> Option<&VersionedRecord> {
        self.0.last()
    }

    /// The newest record of a version up to `version`.
    fn at(&self, version: PolicyVersion) -> Option<&VersionedRecord> {
        self.0.iter().rev().find(|held| held.version <= version)
    }
}

/// The bootstrap state machine.
#[derive(Debug)]
pub struct BootstrapMachine {
    ports: BootstrapPorts,
    phase: Phase,
    next: i64,
    retries: u8,
    newest_epoch: RelayEpoch,
    keys: BTreeMap<StateKey, KeyRecords>,
    /// The offset of the first record of each of the newest versions seen.
    starts: BTreeMap<PolicyVersion, i64>,
}

impl BootstrapMachine {
    /// A machine that has not started.
    #[must_use]
    pub const fn new(ports: BootstrapPorts) -> Self {
        Self::fresh(ports, 0)
    }

    const fn fresh(ports: BootstrapPorts, retries: u8) -> Self {
        Self {
            ports,
            phase: Phase::Idle,
            next: 0,
            retries,
            newest_epoch: RelayEpoch::ZERO,
            keys: BTreeMap::new(),
            starts: BTreeMap::new(),
        }
    }

    /// The step function: the next state and the actions the input asks for.
    #[must_use]
    pub fn step(mut self, input: BootstrapInput) -> (Self, Vec<BootstrapAction>) {
        let actions = self.advance(input);
        (self, actions)
    }

    fn advance(&mut self, input: BootstrapInput) -> Vec<BootstrapAction> {
        match input {
            BootstrapInput::Start => self.start(),
            BootstrapInput::StableEnd(end) => self.stable_end(end),
            BootstrapInput::Records(records) => self.records(records),
            BootstrapInput::ReadFailed(reason) => self.fail(BootstrapFailure::ReadFailed(reason)),
        }
    }

    fn start(&mut self) -> Vec<BootstrapAction> {
        if self.phase != Phase::Idle {
            return Vec::new();
        }
        self.phase = Phase::Capturing { extended: false };
        vec![BootstrapAction::CaptureStableEnd]
    }

    fn stable_end(&mut self, end: i64) -> Vec<BootstrapAction> {
        let Phase::Capturing { extended } = self.phase else {
            return Vec::new();
        };
        if end <= self.next {
            return self.finish(extended);
        }
        self.phase = Phase::Reading {
            extended,
            target: end,
        };
        vec![BootstrapAction::Read {
            from: self.next,
            up_to: end,
        }]
    }

    fn records(&mut self, records: Vec<FramedRecord>) -> Vec<BootstrapAction> {
        let Phase::Reading { extended, target } = self.phase else {
            return Vec::new();
        };
        let resume = Self::resume_after(&records);
        for framed in records {
            self.accept(framed);
        }
        match resume {
            Some(next) if next < target => {
                self.next = next;
                vec![BootstrapAction::Read {
                    from: next,
                    up_to: target,
                }]
            }
            _ => {
                self.next = target;
                self.finish(extended)
            }
        }
    }

    /// The offset to continue from: only a read that returned the most records it may can have
    /// left more of the range behind.
    fn resume_after(records: &[FramedRecord]) -> Option<i64> {
        if records.len() < TAIL_READ_LIMIT {
            return None;
        }
        records.last()?.offset.checked_add(1)
    }

    /// Takes one record. A record of a relay older than one the log already showed is the late
    /// append of a zombie relay and is ignored.
    fn accept(&mut self, framed: FramedRecord) {
        let FramedRecord { offset, record } = framed;
        if record.relay_epoch < self.newest_epoch {
            return;
        }
        self.newest_epoch = record.relay_epoch;
        self.starts.entry(record.version).or_insert(offset);
        while self.starts.len() > KEPT_STARTS {
            self.starts.pop_first();
        }
        self.keys
            .entry(record.key.clone())
            .or_default()
            .offer(record);
    }

    fn finish(&mut self, extended: bool) -> Vec<BootstrapAction> {
        match self.judge() {
            Err(failure) => self.fail(failure),
            Ok(snapshot) if snapshot.incomplete.is_some() && !extended => {
                self.phase = Phase::Capturing { extended: true };
                vec![BootstrapAction::CaptureStableEnd]
            }
            Ok(snapshot) => {
                self.phase = Phase::Done;
                vec![BootstrapAction::Publish(snapshot)]
            }
        }
    }

    /// The first failure starts again from a fresh capture, the second ends the machine.
    fn fail(&mut self, failure: BootstrapFailure) -> Vec<BootstrapAction> {
        if self.retries >= RETRIES {
            self.phase = Phase::Done;
            return vec![BootstrapAction::NotStarted(failure)];
        }
        *self = Self::fresh(self.ports.clone(), self.retries.saturating_add(1));
        self.phase = Phase::Capturing { extended: false };
        vec![
            BootstrapAction::Retry(failure),
            BootstrapAction::CaptureStableEnd,
        ]
    }

    /// The newest head: its version, digest and log epoch; `None` when the topic holds no head.
    fn head(
        &self,
    ) -> Result<Option<(PolicyVersion, PolicyDigestValue, LogEpoch)>, BootstrapFailure> {
        let Some(record) = self.keys.get(&StateKey::Head).and_then(KeyRecords::newest) else {
            return Ok(None);
        };
        let unreadable = BootstrapFailure::UnreadableHead;
        let payload = record
            .payload
            .as_deref()
            .ok_or_else(|| unreadable("the head has no value".to_owned()))?;
        match self.ports.codec.decode(&StateKey::Head, payload) {
            Ok(PolicyState::Head(head)) => Ok(Some((head.version, head.digest, record.log_epoch))),
            Ok(_other) => Err(unreadable("the record is not a head".to_owned())),
            Err(error) => Err(unreadable(error.to_string())),
        }
    }

    /// What the records read so far say.
    fn judge(&self) -> Result<BootstrapSnapshot, BootstrapFailure> {
        let head = self.head()?;
        let version = head.map_or(PolicyVersion::ZERO, |(version, _, _)| version);
        let incomplete = self.trailing(version)?;
        let (entries, computed) = self.state_at(version);
        let expected = head.map_or(PolicyDigestValue::ZERO, |(_, digest, _)| digest);
        if computed != expected {
            return Err(BootstrapFailure::DigestMismatch {
                version: version.value(),
                expected: expected.to_hex(),
                computed: computed.to_hex(),
            });
        }
        Ok(BootstrapSnapshot {
            version,
            log_epoch: head.map_or(LogEpoch::ZERO, |(_, _, epoch)| epoch),
            digest: computed,
            entries,
            incomplete,
            tail_from: incomplete
                .and_then(|trailing| self.starts.get(&trailing).copied())
                .unwrap_or(self.next),
            read_to: self.next,
        })
    }

    /// The version after `version` that a relay left without its head. Any other record above
    /// `version` fails closed.
    fn trailing(&self, version: PolicyVersion) -> Result<Option<PolicyVersion>, BootstrapFailure> {
        let above: Vec<&VersionedRecord> = self
            .keys
            .values()
            .filter_map(KeyRecords::newest)
            .filter(|record| record.version > version)
            .collect();
        let Some(highest) = above.iter().map(|record| record.version).max() else {
            return Ok(None);
        };
        let above_head = || BootstrapFailure::VersionAboveHead {
            version: highest.value(),
        };
        let next = version
            .value()
            .checked_add(1)
            .and_then(|number| PolicyVersion::new(number).ok());
        if next != Some(highest) {
            return Err(above_head());
        }
        let mut assembly = VersionAssembly::new(highest);
        for record in above {
            if matches!(
                assembly.offer(record.clone()),
                Offer::Foreign | Offer::Conflicting
            ) {
                return Err(above_head());
            }
        }
        match assembly.completeness() {
            Completeness::Incomplete { .. } => Ok(Some(highest)),
            Completeness::Complete => Err(above_head()),
        }
    }

    /// The live keys at `version` and the digest they combine to.
    fn state_at(&self, version: PolicyVersion) -> (Vec<BootstrapEntry>, PolicyDigestValue) {
        let mut entries = Vec::new();
        let mut digest = PolicyDigestValue::ZERO;
        for (key, records) in &self.keys {
            if *key == StateKey::Head {
                continue;
            }
            let Some(record) = records.at(version) else {
                continue;
            };
            let Some(payload) = record.payload.as_deref() else {
                continue;
            };
            digest = digest.combined(self.ports.digest.entity_hash(key, payload));
            entries.push(BootstrapEntry {
                key: key.clone(),
                version: record.version,
                payload: payload.to_owned(),
            });
        }
        (entries, digest)
    }
}

#[cfg(test)]
mod tests;
