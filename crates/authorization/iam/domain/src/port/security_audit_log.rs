//! Port of the hash-chained security audit log.

use crate::entity::security_audit_event::{SecurityAuditEvent, StoredSecurityAuditEvent};
use crate::port::RepositoryError;
use crate::value_object::audit_chain_head::AuditChainHead;
use crate::value_object::identifier::SecurityAuditEventId;

/// Appends security audit records to the hash chain and reads them back.
///
/// Records of committed changes are appended in the change's transaction by the unit of work;
/// buffered rejected attempts are appended through [`SecurityAuditLog::append_batch`].
#[async_trait::async_trait]
pub trait SecurityAuditLog: std::fmt::Debug + Send + Sync {
    /// Appends the records in order, in one transaction under the chain-head lock, and returns the
    /// new chain head; an empty batch writes nothing and returns the current head.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::AlreadyExists`] when a record id is already stored, and
    /// [`RepositoryError::Unavailable`] when the storage fails; nothing is appended then.
    async fn append_batch(
        &self,
        events: &[SecurityAuditEvent],
    ) -> Result<AuditChainHead, RepositoryError>;

    /// The newest link of the chain.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn chain_head(&self) -> Result<AuditChainHead, RepositoryError>;

    /// The record with the identifier `id`.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::NotFound`] when no record has that id, and
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_by_id(
        &self,
        id: SecurityAuditEventId,
    ) -> Result<StoredSecurityAuditEvent, RepositoryError>;

    /// At most `limit` records with a sequence number above `after_seq`, oldest first.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_after(
        &self,
        after_seq: i64,
        limit: u32,
    ) -> Result<Vec<StoredSecurityAuditEvent>, RepositoryError>;
}
