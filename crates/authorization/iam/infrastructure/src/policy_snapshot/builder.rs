//! The builder of the policy snapshot (FR-71, NFR-16).
//!
//! It takes the records of the policy state topic, assembles complete versions, applies them to
//! the working state and publishes a snapshot at most once per interval, always at a version
//! boundary.
//!
//! The builder reads no wall clock: the interval is measured on the `BootClock` port. It runs
//! nowhere yet; Story 9.3 drives it on the apply thread.

use std::sync::Arc;
use std::time::Duration;

use iam_domain::{
    ApplyPosition, ApplyRules, BootClock, BootInstant, DigestRing, FenceVerdict,
    InvalidStateRecord, LogEpoch, Offer, PolicyDigest, PolicyDigestValue, PolicyVersion,
    RecordVerdict, RelayEpoch, RouteConflict, RouteTableCompiler, StateKey, StateRecordCodec,
    VersionAssembly, VersionedRecord,
};

use super::arc_swap_policy_snapshot::ArcSwapPolicySnapshot;
use super::data::SnapshotData;
use super::working::{Applier, Working};

/// The shortest time between two published snapshots.
pub const PUBLISH_INTERVAL: Duration = Duration::from_millis(5);

/// The ports of the builder.
#[derive(Debug, Clone)]
pub struct SnapshotPorts {
    /// Decodes the records.
    pub codec: Arc<dyn StateRecordCodec>,
    /// Hashes the entities.
    pub digest: Arc<dyn PolicyDigest>,
    /// Compiles the routes of a host.
    pub compiler: Arc<dyn RouteTableCompiler>,
    /// Measures the publication interval.
    pub boot_clock: Arc<dyn BootClock>,
}

/// Why a complete version was not applied.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SnapshotBuildError {
    /// The digest that the version leads to is not the one its last record carries.
    #[error("digest mismatch at version {version:?}: expected {expected:?}, computed {computed:?}")]
    DigestMismatch {
        /// The version.
        version: PolicyVersion,
        /// The digest the records carry.
        expected: PolicyDigestValue,
        /// The digest the incremental apply computed.
        computed: PolicyDigestValue,
    },
    /// A record cannot be decoded or holds a state that breaks an invariant.
    #[error("a state record is invalid")]
    InvalidRecord(#[from] InvalidStateRecord),
    /// The last record of the version is not its head, or the head names another version.
    #[error("the version does not end with its head")]
    MissingHead,
    /// The routes of a host conflict.
    #[error("the routes of a host conflict")]
    RouteConflict(#[from] RouteConflict),
}

/// What offering one record did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The record was dropped: a repeat, an old relay or an old version.
    Ignored(RecordVerdict),
    /// A record of the version was dropped as a duplicate.
    Duplicate,
    /// The framing of the record is invalid.
    Malformed,
    /// Versions are missing; the published snapshot stays where it is.
    Gap {
        /// The version that must come next.
        expected: PolicyVersion,
    },
    /// The log cannot be trusted: stop and read the topic again.
    Fenced(FenceVerdict),
    /// The record is held; the version is not complete yet.
    Pending {
        /// How many records are missing, when the count is known.
        missing: Option<u32>,
    },
    /// The version was applied.
    Applied {
        /// The version.
        version: PolicyVersion,
        /// Whether a snapshot was published with it.
        published: bool,
    },
    /// The complete version was refused and not applied.
    Rejected(SnapshotBuildError),
}

/// One live key for a full rebuild.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEntry {
    /// The key.
    pub key: StateKey,
    /// The version the key was last changed in.
    pub version: PolicyVersion,
    /// The canonical state.
    pub payload: String,
}

/// Builds the snapshot incrementally from the records of complete versions.
#[derive(Debug)]
pub struct PolicySnapshotBuilder {
    clock: Arc<dyn BootClock>,
    applier: Applier,
    cell: Arc<ArcSwapPolicySnapshot>,
    interval: Duration,
    working: Working,
    ring: DigestRing,
    relay_epoch: RelayEpoch,
    pending: Option<VersionAssembly>,
    published_at: Option<BootInstant>,
    dirty: bool,
}

impl PolicySnapshotBuilder {
    /// A builder that publishes into `cell` at most once per `interval`.
    #[must_use]
    pub fn new(ports: SnapshotPorts, cell: Arc<ArcSwapPolicySnapshot>, interval: Duration) -> Self {
        Self {
            clock: ports.boot_clock,
            applier: Applier::new(ports.codec, ports.digest, ports.compiler),
            cell,
            interval,
            working: Working::empty(LogEpoch::ZERO),
            ring: DigestRing::default(),
            relay_epoch: RelayEpoch::ZERO,
            pending: None,
            published_at: None,
            dirty: false,
        }
    }

    /// The version applied last.
    #[must_use]
    pub const fn applied_version(&self) -> PolicyVersion {
        self.working.version
    }

    /// The digest of the raw state after the version applied last.
    #[must_use]
    pub const fn digest(&self) -> PolicyDigestValue {
        self.working.digest
    }

    /// How many distinct assignment lists the builder interned.
    #[must_use]
    pub fn interned_lists(&self) -> usize {
        self.applier.interned_lists()
    }

    /// Offers one record.
    pub fn offer(&mut self, record: VersionedRecord) -> ApplyOutcome {
        let position = ApplyPosition {
            applied: self.working.version,
            log_epoch: self.working.log_epoch,
            relay_epoch: self.relay_epoch,
        };
        match ApplyRules::judge(&position, &self.ring, &record) {
            RecordVerdict::Next => self.collect(record),
            RecordVerdict::Gap { expected } => ApplyOutcome::Gap { expected },
            RecordVerdict::Fence(verdict) => ApplyOutcome::Fenced(verdict),
            ignored @ (RecordVerdict::AlreadyApplied
            | RecordVerdict::LowerRelayEpoch
            | RecordVerdict::BeyondRing) => ApplyOutcome::Ignored(ignored),
        }
    }

    /// Publishes the applied versions when the interval since the last publication has passed.
    /// Returns whether a snapshot was published.
    pub fn tick(&mut self) -> bool {
        self.publish_if_due()
    }

    /// Publishes the applied versions now, at the version boundary.
    pub fn flush(&mut self) -> bool {
        if !self.dirty {
            return false;
        }
        self.publish();
        true
    }

    /// Replaces the state with the one built from `entries` in one pass, as after a read of the
    /// whole topic, and publishes it. The result equals the one incremental apply reaches.
    ///
    /// # Errors
    ///
    /// Returns the error of the first entry that cannot be applied; nothing changes then.
    pub fn rebuild(
        &mut self,
        entries: &[RawEntry],
        version: PolicyVersion,
        log_epoch: LogEpoch,
    ) -> Result<(), SnapshotBuildError> {
        self.rebuild_expecting(entries, version, log_epoch, None)
    }

    /// Like [`rebuild`](Self::rebuild), and the digest of the entries must equal `expected`, the
    /// digest of the head of `version`: the bootstrap of a pod refuses a state that does not hash
    /// to its head.
    ///
    /// # Errors
    ///
    /// [`SnapshotBuildError::DigestMismatch`] when the digest differs, otherwise the errors of
    /// [`rebuild`](Self::rebuild); nothing changes then.
    pub fn rebuild_verified(
        &mut self,
        entries: &[RawEntry],
        version: PolicyVersion,
        (log_epoch, expected): (LogEpoch, PolicyDigestValue),
    ) -> Result<(), SnapshotBuildError> {
        self.rebuild_expecting(entries, version, log_epoch, Some(expected))
    }

    fn rebuild_expecting(
        &mut self,
        entries: &[RawEntry],
        version: PolicyVersion,
        log_epoch: LogEpoch,
        expected: Option<PolicyDigestValue>,
    ) -> Result<(), SnapshotBuildError> {
        let mut working = Working::empty(log_epoch);
        let changes = entries
            .iter()
            .map(|entry| {
                self.applier
                    .decode(&entry.key, entry.version, Some(&entry.payload))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.applier
            .apply(&mut working, changes, expected, (version, log_epoch))?;
        self.ring = DigestRing::default();
        self.ring.record(version, working.digest);
        self.working = working;
        self.pending = None;
        self.publish();
        Ok(())
    }

    fn collect(&mut self, record: VersionedRecord) -> ApplyOutcome {
        self.relay_epoch = self.relay_epoch.max(record.relay_epoch);
        let version = record.version;
        let mut assembly = self
            .pending
            .take()
            .filter(|held| held.version() == version)
            .unwrap_or_else(|| VersionAssembly::new(version));
        let outcome = match assembly.offer(record) {
            Offer::Added => return self.after_added(assembly),
            Offer::Conflicting => ApplyOutcome::Fenced(FenceVerdict::ConflictingContent),
            Offer::Foreign => ApplyOutcome::Malformed,
            Offer::Duplicate => ApplyOutcome::Duplicate,
        };
        self.pending = Some(assembly);
        outcome
    }

    fn after_added(&mut self, assembly: VersionAssembly) -> ApplyOutcome {
        match assembly.completeness() {
            iam_domain::Completeness::Incomplete { missing } => {
                self.pending = Some(assembly);
                ApplyOutcome::Pending { missing }
            }
            iam_domain::Completeness::Complete => match self.apply_version(&assembly) {
                Ok(version) => {
                    self.ring.record(version, self.working.digest);
                    self.dirty = true;
                    ApplyOutcome::Applied {
                        version,
                        published: self.publish_if_due(),
                    }
                }
                Err(error) => ApplyOutcome::Rejected(error),
            },
        }
    }

    fn apply_version(
        &mut self,
        assembly: &VersionAssembly,
    ) -> Result<PolicyVersion, SnapshotBuildError> {
        let version = assembly.version();
        let records = assembly.records();
        let (last, body) = records
            .split_last()
            .ok_or(SnapshotBuildError::MissingHead)?;
        let payload = last
            .payload
            .as_deref()
            .filter(|_payload| last.key == StateKey::Head)
            .ok_or(SnapshotBuildError::MissingHead)?;
        let head = self.applier.head(payload)?;
        if head.version != version {
            return Err(SnapshotBuildError::MissingHead);
        }
        if head.digest != last.digest_after {
            return Err(SnapshotBuildError::DigestMismatch {
                version,
                expected: last.digest_after,
                computed: head.digest,
            });
        }
        let changes = body
            .iter()
            .map(|record| {
                self.applier
                    .decode(&record.key, record.version, record.payload.as_deref())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let log_epoch = assembly.log_epoch().unwrap_or(self.working.log_epoch);
        self.applier.apply(
            &mut self.working,
            changes,
            Some(last.digest_after),
            (version, log_epoch),
        )?;
        Ok(version)
    }

    fn publish_if_due(&mut self) -> bool {
        if !self.dirty {
            return false;
        }
        let due = self
            .published_at
            .is_none_or(|last| self.clock.now().saturating_since(last) >= self.interval);
        if due {
            self.publish();
        }
        due
    }

    fn publish(&mut self) {
        let now = self.clock.now();
        self.working.shards.take_copies();
        self.cell
            .publish(Arc::new(SnapshotData::new(self.working.clone(), now)));
        self.published_at = Some(now);
        self.dirty = false;
    }
}

#[cfg(test)]
mod tests;
