//! The newest link of the security audit hash chain.

use crate::error::InvalidIamValue;
use crate::value_object::audit_hash::AuditHash;

/// The sequence number and hash of the newest audit record; sequence 0 and the genesis hash before
/// the first record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditChainHead {
    seq: i64,
    hash: AuditHash,
}

impl AuditChainHead {
    /// The head of an empty chain.
    pub const GENESIS: Self = Self {
        seq: 0,
        hash: AuditHash::GENESIS,
    };

    /// Builds the head.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::AuditSequence`] when `seq` is negative.
    pub const fn new(seq: i64, hash: AuditHash) -> Result<Self, InvalidIamValue> {
        if seq < 0 {
            return Err(InvalidIamValue::AuditSequence);
        }
        Ok(Self { seq, hash })
    }

    /// The sequence number of the newest record, 0 for an empty chain.
    #[must_use]
    pub const fn seq(&self) -> i64 {
        self.seq
    }

    /// The hash of the newest record, the genesis hash for an empty chain.
    #[must_use]
    pub const fn hash(&self) -> AuditHash {
        self.hash
    }
}

#[cfg(test)]
mod tests;
