//! Policy inventory double of the IAM context: the entities a resync publishes, held in memory.

use std::sync::{Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use iam_domain::{InventoryEntry, PolicyStateInventory, RepositoryError};

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// An inventory that lists its entries in the order it was given them.
#[derive(Debug, Default)]
pub struct FakePolicyStateInventory {
    entries: Mutex<Vec<InventoryEntry>>,
    failing: bool,
}

impl FakePolicyStateInventory {
    /// An inventory without entries.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            failing: false,
        }
    }

    /// An inventory that lists `entries`.
    #[must_use]
    pub const fn holding(entries: Vec<InventoryEntry>) -> Self {
        Self {
            entries: Mutex::new(entries),
            failing: false,
        }
    }

    /// An inventory that answers `Unavailable`.
    #[must_use]
    pub const fn failing() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            failing: true,
        }
    }

    /// Replaces the entries, as when the policy changes between two chunks.
    pub fn replace(&self, entries: Vec<InventoryEntry>) {
        *locked(&self.entries) = entries;
    }

    fn check(&self) -> Result<(), RepositoryError> {
        if self.failing {
            return Err(RepositoryError::Unavailable("the fake is failing".into()));
        }
        Ok(())
    }
}

#[async_trait]
impl PolicyStateInventory for FakePolicyStateInventory {
    async fn count(&self) -> Result<u64, RepositoryError> {
        self.check()?;
        Ok(u64::try_from(locked(&self.entries).len()).unwrap_or(u64::MAX))
    }

    async fn page(&self, offset: u64, limit: u64) -> Result<Vec<InventoryEntry>, RepositoryError> {
        self.check()?;
        let entries = locked(&self.entries);
        let skip = usize::try_from(offset).unwrap_or(usize::MAX);
        let take = usize::try_from(limit).unwrap_or(usize::MAX);
        Ok(entries.iter().skip(skip).take(take).cloned().collect())
    }
}
