//! The apply rules: what an offered record means for a builder that is at a known position.

use crate::snapshot::assembly::VersionedRecord;
use crate::snapshot::ring::DigestRing;
use crate::value_object::log_epoch::LogEpoch;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::relay_epoch::RelayEpoch;

/// Why the log cannot be trusted any more: the builder stops and the process restarts from a
/// fresh read of the topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceVerdict {
    /// A record of an applied version carries other content than the one applied.
    ConflictingContent,
    /// A record carries a log epoch lower than the one the builder follows.
    LowerLogEpoch,
}

/// What the builder does with one offered record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordVerdict {
    /// The record belongs to the next version: it goes to the assembly.
    Next,
    /// The record repeats an applied version with the same digest: ignored.
    AlreadyApplied,
    /// The record comes from a relay older than one already seen: ignored.
    LowerRelayEpoch,
    /// The record is for an applied version that the ring no longer remembers: ignored.
    BeyondRing,
    /// Versions are missing between the applied one and the record's.
    Gap {
        /// The version that must come next.
        expected: PolicyVersion,
    },
    /// The log is not trustworthy.
    Fence(FenceVerdict),
}

impl RecordVerdict {
    /// Whether the verdict fences the builder.
    #[must_use]
    pub const fn is_fence(self) -> bool {
        matches!(self, Self::Fence(_))
    }
}

/// Where the builder is: the version applied last and the epochs it follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyPosition {
    /// The version applied last.
    pub applied: PolicyVersion,
    /// The log epoch of the applied records.
    pub log_epoch: LogEpoch,
    /// The highest relay epoch seen so far.
    pub relay_epoch: RelayEpoch,
}

/// The apply rules of FR-71.
#[derive(Debug, Clone, Copy)]
pub struct ApplyRules;

impl ApplyRules {
    /// The per-key version guard: a record changes its key only when its version is higher than
    /// the version the key already has, so the highest version wins.
    #[must_use]
    pub fn admits(current: Option<PolicyVersion>, incoming: PolicyVersion) -> bool {
        current.is_none_or(|current| incoming > current)
    }

    /// Judges one record. A lower log epoch fences, then a lower relay epoch is ignored; a record
    /// of an applied version is compared with the ring; a record of the next version proceeds and
    /// any later one is a gap.
    #[must_use]
    pub fn judge(
        position: &ApplyPosition,
        ring: &DigestRing,
        record: &VersionedRecord,
    ) -> RecordVerdict {
        if record.log_epoch < position.log_epoch {
            return RecordVerdict::Fence(FenceVerdict::LowerLogEpoch);
        }
        if record.relay_epoch < position.relay_epoch {
            return RecordVerdict::LowerRelayEpoch;
        }
        let Some(expected) = position
            .applied
            .value()
            .checked_add(1)
            .and_then(|next| PolicyVersion::new(next).ok())
        else {
            return RecordVerdict::BeyondRing;
        };
        if record.version == expected {
            return RecordVerdict::Next;
        }
        if record.version > expected {
            return RecordVerdict::Gap { expected };
        }
        Self::judge_applied(ring, record)
    }

    /// A record of an applied version is a repeat only when the digest after it is the one the
    /// ring holds for that version. The digest after a record is the one of its version only for
    /// the last record, so the comparison is for the records that carry the version's end.
    fn judge_applied(ring: &DigestRing, record: &VersionedRecord) -> RecordVerdict {
        match ring.get(record.version) {
            None => RecordVerdict::BeyondRing,
            Some(_) if record.seq != record.count => RecordVerdict::AlreadyApplied,
            Some(digest) if digest == record.digest_after => RecordVerdict::AlreadyApplied,
            Some(_) => RecordVerdict::Fence(FenceVerdict::ConflictingContent),
        }
    }
}

#[cfg(test)]
mod tests;
