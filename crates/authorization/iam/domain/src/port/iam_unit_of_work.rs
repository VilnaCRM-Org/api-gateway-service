//! Port of the unit of work that commits an administrative change atomically.

use crate::entity::change_receipt::ChangeReceipt;
use crate::entity::iam_change::IamChange;
use crate::port::RepositoryError;

/// Commits an administrative change in one transaction.
///
/// It locks the policy version and takes the next one when the change affects decisions, runs the
/// statements, writes the outbox event rows, the audit record, the change receipt and the
/// idempotency record (FR-2, FR-46, FR-47, FR-49). Either all of them become visible or none.
#[async_trait::async_trait]
pub trait IamUnitOfWork: std::fmt::Debug + Send + Sync {
    /// Commits the change and returns its receipt. An idempotency record of the actor's key that
    /// is older than [`IdempotencyRecord::WINDOW`](crate::IdempotencyRecord::WINDOW) at the time of
    /// the change is expired: the change replaces it.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Conflict`] when a statement does not hold,
    /// [`RepositoryError::AlreadyExists`] when the change id, an event id, the audit record id or
    /// an idempotency key of the actor that has not expired is already stored, and [`RepositoryError::Unavailable`]
    /// when the storage fails, holds unusable data or an event cannot be encoded; nothing is
    /// written then.
    async fn commit(&self, change: IamChange) -> Result<ChangeReceipt, RepositoryError>;
}
