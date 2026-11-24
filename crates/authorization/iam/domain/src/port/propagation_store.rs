//! Port of the publication state of a write: the stored offset of a version's `__head` row and
//! the outcome that a change receipt keeps (FR-75).

use crate::port::RepositoryError;
use crate::value_object::identifier::ChangeId;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::propagation_outcome::PropagationOutcome;

/// Reads what the relay stored for a policy version and records the outcome of a write.
#[async_trait::async_trait]
pub trait PropagationStore: std::fmt::Debug + Send + Sync {
    /// The offset at which the relay stored the `__head` row of `version`, none while the row is
    /// not marked published (with the transactional relay, until its transaction committed).
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn published_head_offset(
        &self,
        version: PolicyVersion,
    ) -> Result<Option<i64>, RepositoryError>;

    /// Stores `outcome` on the receipt of the change `change_id`.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::NotFound`] when no receipt of that change exists, and
    /// [`RepositoryError::Unavailable`] when the storage fails.
    async fn record(
        &self,
        change_id: ChangeId,
        outcome: PropagationOutcome,
    ) -> Result<(), RepositoryError>;
}
