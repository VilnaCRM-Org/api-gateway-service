//! The progress write of a bulk operation that a chunk's change hands to the unit of work.

use crate::bulk_operation::{BulkOperation, BulkOperationParts};

/// The write of the progress of one bulk operation: the state after a committed chunk, guarded by
/// the number of records that the stored operation had applied before the chunk.
///
/// The progress commits in the transaction of the chunk, so a chunk is never applied twice and a
/// restart resumes from the applied records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkProgressStatement {
    operation: BulkOperationParts,
    expected_applied: u64,
}

impl BulkProgressStatement {
    /// The write of `operation` as it stands after a chunk, over a stored operation that had
    /// applied `expected_applied` records.
    #[must_use]
    pub fn after_chunk(operation: &BulkOperation, expected_applied: u64) -> Self {
        Self {
            operation: operation.parts().clone(),
            expected_applied,
        }
    }

    /// The state of the operation to store.
    #[must_use]
    pub const fn operation(&self) -> &BulkOperationParts {
        &self.operation
    }

    /// The records the stored operation must have applied; any other stored progress refuses the
    /// change as a conflict.
    #[must_use]
    pub const fn expected_applied(&self) -> u64 {
        self.expected_applied
    }
}

#[cfg(test)]
mod tests;
