//! Port of the storage work of the periodic maintenance: the grants that stayed orphaned long
//! enough, the expired records and the anchoring of the audit chain.

use std::time::SystemTime;

use crate::audit_anchor::AnchorStamp;
use crate::maintenance::{ExpiredOrphanedGrant, PurgedRecords, RetentionCutoffs};
use crate::port::RepositoryError;
use crate::value_object::audit_chain_head::AuditChainHead;

/// Reads and removes what the maintenance task keeps small.
///
/// The orphaned grants leave through the [`IamUnitOfWork`](crate::IamUnitOfWork), as changes of
/// their roles with an audit record each; this port only finds them.
#[async_trait::async_trait]
pub trait MaintenanceStore: std::fmt::Debug + Send + Sync {
    /// At most `limit` grants of roles that are not deleted whose `orphaned_at` is strictly before
    /// `orphaned_before` and that are still inactive, oldest first.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn expired_orphaned_grants(
        &self,
        orphaned_before: SystemTime,
        limit: u32,
    ) -> Result<Vec<ExpiredOrphanedGrant>, RepositoryError>;

    /// Removes, in one transaction, the idempotency records and change receipts created before
    /// their cut-offs and the inbound-event ids processed before theirs, and counts them. Session
    /// revocations and cut-offs of any age stay.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails; nothing is removed then.
    async fn purge_expired_records(
        &self,
        cutoffs: &RetentionCutoffs,
    ) -> Result<PurgedRecords, RepositoryError>;

    /// Reads the current head of the audit chain and, in the same transaction, writes the outbox
    /// event `iam.security_audit.anchored` that carries it; returns the anchored head.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::AlreadyExists`] when the event id is already stored and
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data; nothing is
    /// written then.
    async fn anchor_audit_chain(
        &self,
        stamp: AnchorStamp,
    ) -> Result<AuditChainHead, RepositoryError>;
}
