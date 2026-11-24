//! Bulk operation repository and chunk committer doubles of the IAM context.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use iam_domain::{
    BulkChunkCommitter, BulkOperation, BulkOperationId, BulkOperationParts,
    BulkOperationRepository, BulkRoleTargetStore, BulkStamp, ChunkCommitError, CommittedChunk,
    PolicyVersion, RepositoryError, RoleId,
};

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A repository that keeps the operations in memory, in creation (id) order.
#[derive(Debug, Default)]
pub struct FakeBulkOperationRepository {
    stored: Mutex<Vec<BulkOperationParts>>,
    failing: bool,
}

impl FakeBulkOperationRepository {
    /// A repository without operations.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            stored: Mutex::new(Vec::new()),
            failing: false,
        }
    }

    /// A repository that holds `operations`.
    #[must_use]
    pub fn holding(operations: &[BulkOperation]) -> Self {
        let mut stored: Vec<_> = operations.iter().map(|op| op.parts().clone()).collect();
        stored.sort_by_key(|parts| parts.id);
        Self {
            stored: Mutex::new(stored),
            failing: false,
        }
    }

    /// A repository that answers `Unavailable`.
    #[must_use]
    pub const fn failing() -> Self {
        Self {
            stored: Mutex::new(Vec::new()),
            failing: true,
        }
    }

    /// The stored state of every operation, in creation order.
    #[must_use]
    pub fn snapshot(&self) -> Vec<BulkOperationParts> {
        locked(&self.stored).clone()
    }

    fn check(&self) -> Result<(), RepositoryError> {
        if self.failing {
            return Err(RepositoryError::Unavailable("the fake is failing".into()));
        }
        Ok(())
    }
}

fn rebuilt(parts: BulkOperationParts) -> Result<BulkOperation, RepositoryError> {
    BulkOperation::restore(parts).map_err(|error| RepositoryError::Unavailable(Box::new(error)))
}

#[async_trait]
impl BulkOperationRepository for FakeBulkOperationRepository {
    async fn insert(&self, operation: &BulkOperation) -> Result<(), RepositoryError> {
        self.check()?;
        let mut stored = locked(&self.stored);
        if stored.iter().any(|parts| parts.id == operation.parts().id) {
            return Err(RepositoryError::AlreadyExists);
        }
        stored.push(operation.parts().clone());
        stored.sort_by_key(|parts| parts.id);
        drop(stored);
        Ok(())
    }

    async fn save(&self, operation: &BulkOperation) -> Result<(), RepositoryError> {
        self.check()?;
        let mut stored = locked(&self.stored);
        let slot = stored
            .iter_mut()
            .find(|parts| parts.id == operation.parts().id)
            .ok_or(RepositoryError::NotFound)?;
        *slot = operation.parts().clone();
        drop(stored);
        Ok(())
    }

    async fn find(&self, id: BulkOperationId) -> Result<Option<BulkOperation>, RepositoryError> {
        self.check()?;
        let found = locked(&self.stored)
            .iter()
            .find(|parts| parts.id == id)
            .cloned();
        found.map(rebuilt).transpose()
    }

    async fn list(
        &self,
        after: Option<BulkOperationId>,
        limit: u32,
    ) -> Result<Vec<BulkOperation>, RepositoryError> {
        self.check()?;
        locked(&self.stored)
            .iter()
            .filter(|parts| after.is_none_or(|after| parts.id > after))
            .take(usize::try_from(limit).unwrap_or(usize::MAX))
            .cloned()
            .map(rebuilt)
            .collect()
    }

    async fn oldest_unfinished(&self) -> Result<Option<BulkOperation>, RepositoryError> {
        self.check()?;
        let found = locked(&self.stored)
            .iter()
            .find(|parts| !parts.status.is_finished())
            .cloned();
        found.map(rebuilt).transpose()
    }
}

/// What the committer double does with the next chunk.
#[derive(Debug, Clone)]
pub enum ChunkBehaviour {
    /// Commits chunks of at most this many records.
    Commit(u64),
    /// Refuses the change for good with this reason.
    Refuse(String),
    /// Fails like an unavailable storage.
    Unavailable,
}

/// A committer that applies chunks to a [`FakeBulkOperationRepository`] the way the real one does:
/// it records the progress of the operation, takes the next policy version and remembers its calls.
#[derive(Debug)]
pub struct FakeChunkCommitter {
    operations: Arc<FakeBulkOperationRepository>,
    behaviour: ChunkBehaviour,
    next_version: Mutex<i64>,
    commits: Mutex<Vec<CommittedChunk>>,
}

impl FakeChunkCommitter {
    /// A committer over `operations` that takes policy versions from `first_version` upward.
    #[must_use]
    pub const fn new(
        operations: Arc<FakeBulkOperationRepository>,
        behaviour: ChunkBehaviour,
        first_version: i64,
    ) -> Self {
        Self {
            operations,
            behaviour,
            next_version: Mutex::new(first_version),
            commits: Mutex::new(Vec::new()),
        }
    }

    /// The chunks committed so far, in order.
    #[must_use]
    pub fn commits(&self) -> Vec<CommittedChunk> {
        locked(&self.commits).clone()
    }
}

#[async_trait]
impl BulkChunkCommitter for FakeChunkCommitter {
    async fn commit_next_chunk(
        &self,
        operation: &BulkOperation,
        stamp: BulkStamp,
    ) -> Result<CommittedChunk, ChunkCommitError> {
        let size = match &self.behaviour {
            ChunkBehaviour::Commit(size) => *size,
            ChunkBehaviour::Refuse(reason) => {
                return Err(ChunkCommitError::Permanent(reason.clone()));
            }
            ChunkBehaviour::Unavailable => {
                return Err(ChunkCommitError::Unavailable("the fake is failing".into()));
            }
        };
        let mut next = BulkOperation::restore(operation.parts().clone())
            .map_err(|error| ChunkCommitError::Permanent(error.to_string()))?;
        let records = size.min(next.remaining_records());
        let version = {
            let mut counter = locked(&self.next_version);
            let version = *counter;
            *counter = counter.saturating_add(1);
            drop(counter);
            PolicyVersion::new(version)
                .map_err(|error| ChunkCommitError::Permanent(error.to_string()))?
        };
        next.record_chunk(records, version, stamp)
            .map_err(|error| ChunkCommitError::Permanent(error.to_string()))?;
        self.operations
            .save(&next)
            .await
            .map_err(|error| ChunkCommitError::Unavailable(Box::new(error)))?;
        let chunk = CommittedChunk { records, version };
        locked(&self.commits).push(chunk);
        Ok(chunk)
    }
}

/// A target store that keeps the role of each operation in memory.
#[derive(Debug, Default)]
pub struct FakeBulkRoleTargetStore {
    stored: Mutex<Vec<(BulkOperationId, RoleId)>>,
    failing: bool,
}

impl FakeBulkRoleTargetStore {
    /// A store without targets.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            stored: Mutex::new(Vec::new()),
            failing: false,
        }
    }

    /// A store that answers `Unavailable`.
    #[must_use]
    pub const fn failing() -> Self {
        Self {
            stored: Mutex::new(Vec::new()),
            failing: true,
        }
    }

    /// A store that holds `role` as the target of `operation`.
    #[must_use]
    pub fn holding(operation: BulkOperationId, role: RoleId) -> Self {
        Self {
            stored: Mutex::new(vec![(operation, role)]),
            failing: false,
        }
    }

    fn check(&self) -> Result<(), RepositoryError> {
        if self.failing {
            return Err(RepositoryError::Unavailable("the fake is failing".into()));
        }
        Ok(())
    }
}

#[async_trait]
impl BulkRoleTargetStore for FakeBulkRoleTargetStore {
    async fn insert(
        &self,
        operation: BulkOperationId,
        role: RoleId,
    ) -> Result<(), RepositoryError> {
        self.check()?;
        let mut stored = locked(&self.stored);
        if stored.iter().any(|(id, _role)| *id == operation) {
            return Err(RepositoryError::AlreadyExists);
        }
        stored.push((operation, role));
        drop(stored);
        Ok(())
    }

    async fn find(&self, operation: BulkOperationId) -> Result<Option<RoleId>, RepositoryError> {
        self.check()?;
        Ok(locked(&self.stored)
            .iter()
            .find(|(id, _role)| *id == operation)
            .map(|(_id, role)| *role))
    }
}
