//! Maintenance store double of the IAM context.

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;

use async_trait::async_trait;
use iam_domain::{
    AnchorStamp, AuditChainHead, ExpiredOrphanedGrant, MaintenanceStore, PurgedRecords,
    RepositoryError, RetentionCutoffs,
};

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The operation of the store that fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failing {
    /// Finding the expired orphaned grants.
    Orphans,
    /// Purging the expired records.
    Purge,
    /// Anchoring the audit chain.
    Anchor,
}

/// What the double was asked, in the order of the calls of each kind.
#[derive(Debug, Default)]
struct Book {
    orphan_requests: Vec<(SystemTime, u32)>,
    cutoffs: Vec<RetentionCutoffs>,
    anchors: Vec<AnchorStamp>,
}

/// A maintenance store that answers from memory with the rules of the port and records its calls.
#[derive(Debug)]
pub struct FakeMaintenanceStore {
    orphans: Vec<ExpiredOrphanedGrant>,
    purged: PurgedRecords,
    head: AuditChainHead,
    failing: Option<Failing>,
    book: Mutex<Book>,
}

impl FakeMaintenanceStore {
    /// A store without orphaned grants, that purges no record and anchors the genesis head.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            orphans: Vec::new(),
            purged: PurgedRecords {
                idempotency_records: 0,
                change_receipts: 0,
                inbound_events: 0,
            },
            head: AuditChainHead::GENESIS,
            failing: None,
            book: Mutex::new(Book {
                orphan_requests: Vec::new(),
                cutoffs: Vec::new(),
                anchors: Vec::new(),
            }),
        }
    }

    /// The same store holding `orphans`, as the grants of roles that are orphaned.
    #[must_use]
    pub fn with_orphans(mut self, orphans: Vec<ExpiredOrphanedGrant>) -> Self {
        self.orphans = orphans;
        self
    }

    /// The same store that reports `purged` for every purge of records.
    #[must_use]
    pub const fn with_purged(mut self, purged: PurgedRecords) -> Self {
        self.purged = purged;
        self
    }

    /// The same store whose audit chain ends at `head`.
    #[must_use]
    pub const fn with_head(mut self, head: AuditChainHead) -> Self {
        self.head = head;
        self
    }

    /// The same store whose `operation` answers `Unavailable`.
    #[must_use]
    pub const fn failing(mut self, operation: Failing) -> Self {
        self.failing = Some(operation);
        self
    }

    /// The `(orphaned before, limit)` of every search for orphaned grants.
    #[must_use]
    pub fn orphan_requests(&self) -> Vec<(SystemTime, u32)> {
        locked(&self.book).orphan_requests.clone()
    }

    /// The cut-offs of every purge of records.
    #[must_use]
    pub fn cutoffs(&self) -> Vec<RetentionCutoffs> {
        locked(&self.book).cutoffs.clone()
    }

    /// The stamp of every anchoring.
    #[must_use]
    pub fn anchors(&self) -> Vec<AnchorStamp> {
        locked(&self.book).anchors.clone()
    }

    fn check(&self, operation: Failing) -> Result<(), RepositoryError> {
        if self.failing == Some(operation) {
            return Err(RepositoryError::Unavailable(
                "in-memory maintenance store failure".into(),
            ));
        }
        Ok(())
    }
}

impl Default for FakeMaintenanceStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MaintenanceStore for FakeMaintenanceStore {
    async fn expired_orphaned_grants(
        &self,
        orphaned_before: SystemTime,
        limit: u32,
    ) -> Result<Vec<ExpiredOrphanedGrant>, RepositoryError> {
        locked(&self.book)
            .orphan_requests
            .push((orphaned_before, limit));
        self.check(Failing::Orphans)?;
        let mut expired: Vec<ExpiredOrphanedGrant> = self
            .orphans
            .iter()
            .filter(|orphan| orphan.orphaned_at < orphaned_before)
            .cloned()
            .collect();
        expired.sort_by_key(|orphan| orphan.orphaned_at);
        expired.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(expired)
    }

    async fn purge_expired_records(
        &self,
        cutoffs: &RetentionCutoffs,
    ) -> Result<PurgedRecords, RepositoryError> {
        locked(&self.book).cutoffs.push(*cutoffs);
        self.check(Failing::Purge)?;
        Ok(self.purged)
    }

    async fn anchor_audit_chain(
        &self,
        stamp: AnchorStamp,
    ) -> Result<AuditChainHead, RepositoryError> {
        self.check(Failing::Anchor)?;
        locked(&self.book).anchors.push(stamp);
        Ok(self.head)
    }
}

#[cfg(test)]
mod tests;
