//! The result of verifying the security audit hash chain (FR-52).

use crate::value_object::identifier::SecurityAuditEventId;

/// How the chain is broken at a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainBreakCause {
    /// The sequence number does not follow the one before it: a record is missing.
    Gap,
    /// The `prev_hash` of the record is not the hash of the record before it.
    Link,
    /// The hash of the record is not `SHA-256(prev_hash || canonical form)` of its stored values.
    Digest,
    /// The stored values of the record cannot be read back as a valid record.
    Unreadable,
    /// The hash of the record differs from the external anchor of its sequence number.
    Anchor,
    /// An anchor names a sequence number beyond the newest record: records were removed.
    AnchorMissing,
}

impl ChainBreakCause {
    /// The machine-readable name of the cause.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gap => "gap",
            Self::Link => "link",
            Self::Digest => "digest",
            Self::Unreadable => "unreadable",
            Self::Anchor => "anchor",
            Self::AnchorMissing => "anchor_missing",
        }
    }
}

/// The first place where the chain does not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainBreak {
    seq: i64,
    record: Option<SecurityAuditEventId>,
    cause: ChainBreakCause,
}

impl ChainBreak {
    /// A break at the record `record` with the sequence number `seq`; `record` is absent when the
    /// record itself is missing.
    #[must_use]
    pub const fn new(
        seq: i64,
        record: Option<SecurityAuditEventId>,
        cause: ChainBreakCause,
    ) -> Self {
        Self { seq, record, cause }
    }

    /// The sequence number where the chain breaks.
    #[must_use]
    pub const fn seq(&self) -> i64 {
        self.seq
    }

    /// The id of the record where the chain breaks; none when the record is missing.
    #[must_use]
    pub const fn record(&self) -> Option<SecurityAuditEventId> {
        self.record
    }

    /// Why the chain breaks there.
    #[must_use]
    pub const fn cause(&self) -> ChainBreakCause {
        self.cause
    }
}

/// Whether the chain verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainVerdict {
    /// Every record, every link and every anchor checked out.
    Valid,
    /// The chain breaks at the given place.
    Invalid(ChainBreak),
}

/// The outcome of one verification: how many records were checked and whether the chain holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainVerification {
    records_checked: i64,
    verdict: ChainVerdict,
}

impl ChainVerification {
    /// A chain of `records_checked` records that verified.
    #[must_use]
    pub const fn valid(records_checked: i64) -> Self {
        Self {
            records_checked,
            verdict: ChainVerdict::Valid,
        }
    }

    /// A chain that broke at `broken` after `records_checked` records were checked, the broken one
    /// included when the record exists.
    #[must_use]
    pub const fn invalid(records_checked: i64, broken: ChainBreak) -> Self {
        Self {
            records_checked,
            verdict: ChainVerdict::Invalid(broken),
        }
    }

    /// The number of records checked.
    #[must_use]
    pub const fn records_checked(&self) -> i64 {
        self.records_checked
    }

    /// The verdict.
    #[must_use]
    pub const fn verdict(&self) -> &ChainVerdict {
        &self.verdict
    }

    /// Whether the chain verified.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        matches!(self.verdict, ChainVerdict::Valid)
    }
}

#[cfg(test)]
mod tests;
