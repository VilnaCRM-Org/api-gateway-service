//! Repository port of the change receipts.

use crate::entity::change_receipt::ChangeReceipt;
use crate::port::RepositoryError;
use crate::value_object::identifier::ChangeId;

/// Reads the receipts that the unit of work stores with each committed change.
#[async_trait::async_trait]
pub trait ChangeReceiptRepository: std::fmt::Debug + Send + Sync {
    /// Returns the receipt of the change `change_id`.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::NotFound`] when no change with that id was committed, and
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find(&self, change_id: ChangeId) -> Result<ChangeReceipt, RepositoryError>;
}
