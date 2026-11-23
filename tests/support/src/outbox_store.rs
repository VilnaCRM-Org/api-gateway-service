//! Outbox store double of the IAM context.

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;

use async_trait::async_trait;
use iam_domain::{
    OutboxRow, OutboxStore, PublishedRow, RelayEpoch, RelayTakeover, RepositoryError,
};

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The operation of the store that fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failing {
    /// Claiming the unpublished rows.
    Claim,
    /// Reading the relay epoch.
    Epoch,
    /// Taking the relay over.
    Takeover,
    /// Marking rows published.
    Mark,
    /// Deleting published rows.
    Delete,
}

#[derive(Debug)]
struct Book {
    unpublished: Vec<OutboxRow>,
    published: Vec<(PublishedRow, RelayEpoch)>,
    epoch: i64,
    takeovers: u32,
    deleted_before: Vec<SystemTime>,
}

/// An outbox that answers from memory with the rules of the port and records its calls.
#[derive(Debug)]
pub struct FakeOutboxStore {
    republish: Vec<OutboxRow>,
    failing: Option<Failing>,
    book: Mutex<Book>,
}

impl FakeOutboxStore {
    /// An empty outbox whose relay epoch is 0.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            republish: Vec::new(),
            failing: None,
            book: Mutex::new(Book {
                unpublished: Vec::new(),
                published: Vec::new(),
                epoch: 0,
                takeovers: 0,
                deleted_before: Vec::new(),
            }),
        }
    }

    /// The same store holding `rows` as unpublished rows.
    #[must_use]
    pub fn with_rows(self, rows: Vec<OutboxRow>) -> Self {
        locked(&self.book).unpublished = rows;
        self
    }

    /// The same store whose relay epoch is `epoch`.
    #[must_use]
    pub fn with_epoch(self, epoch: i64) -> Self {
        locked(&self.book).epoch = epoch;
        self
    }

    /// The same store that hands `rows` to a relay that takes over.
    #[must_use]
    pub fn with_republish(mut self, rows: Vec<OutboxRow>) -> Self {
        self.republish = rows;
        self
    }

    /// The same store whose `operation` fails.
    #[must_use]
    pub const fn failing(mut self, operation: Failing) -> Self {
        self.failing = Some(operation);
        self
    }

    /// Moves the relay epoch as another relay that took over would.
    pub fn another_relay_takes_over(&self) {
        let mut book = locked(&self.book);
        book.epoch = book.epoch.saturating_add(1);
    }

    /// The rows that were marked published, with the epoch of each mark.
    #[must_use]
    pub fn published(&self) -> Vec<(PublishedRow, RelayEpoch)> {
        locked(&self.book).published.clone()
    }

    /// How many rows are still unpublished.
    #[must_use]
    pub fn unpublished(&self) -> usize {
        locked(&self.book).unpublished.len()
    }

    /// The relay epoch now.
    #[must_use]
    pub fn epoch(&self) -> i64 {
        locked(&self.book).epoch
    }

    /// How many times a relay took over.
    #[must_use]
    pub fn takeovers(&self) -> u32 {
        locked(&self.book).takeovers
    }

    /// The cut-off of every deletion of published rows.
    #[must_use]
    pub fn deleted_before(&self) -> Vec<SystemTime> {
        locked(&self.book).deleted_before.clone()
    }

    fn check(&self, operation: Failing) -> Result<(), RepositoryError> {
        if self.failing == Some(operation) {
            return Err(RepositoryError::Unavailable(
                "in-memory outbox failure".into(),
            ));
        }
        Ok(())
    }
}

impl Default for FakeOutboxStore {
    fn default() -> Self {
        Self::new()
    }
}

fn epoch_of(value: i64) -> Result<RelayEpoch, RepositoryError> {
    RelayEpoch::new(value).map_err(|error| RepositoryError::Unavailable(Box::new(error)))
}

#[async_trait]
impl OutboxStore for FakeOutboxStore {
    async fn claim_unpublished(&self, limit: u32) -> Result<Vec<OutboxRow>, RepositoryError> {
        self.check(Failing::Claim)?;
        let book = locked(&self.book);
        Ok(book
            .unpublished
            .iter()
            .take(usize::try_from(limit).unwrap_or(usize::MAX))
            .cloned()
            .collect())
    }

    async fn current_relay_epoch(&self) -> Result<RelayEpoch, RepositoryError> {
        self.check(Failing::Epoch)?;
        epoch_of(locked(&self.book).epoch)
    }

    async fn take_over_relay(&self) -> Result<RelayTakeover, RepositoryError> {
        self.check(Failing::Takeover)?;
        let mut book = locked(&self.book);
        book.epoch = book.epoch.saturating_add(1);
        book.takeovers = book.takeovers.saturating_add(1);
        Ok(RelayTakeover {
            epoch: epoch_of(book.epoch)?,
            republish: self.republish.clone(),
        })
    }

    async fn mark_published(
        &self,
        published: &[PublishedRow],
        epoch: RelayEpoch,
        _at: SystemTime,
    ) -> Result<(), RepositoryError> {
        self.check(Failing::Mark)?;
        let mut book = locked(&self.book);
        if book.epoch != epoch.value() {
            return Err(RepositoryError::Conflict);
        }
        for row in published {
            book.unpublished
                .retain(|unpublished| unpublished.id != row.id);
            book.published.push((*row, epoch));
        }
        drop(book);
        Ok(())
    }

    async fn delete_published_before(&self, before: SystemTime) -> Result<u64, RepositoryError> {
        self.check(Failing::Delete)?;
        locked(&self.book).deleted_before.push(before);
        Ok(0)
    }
}

#[cfg(test)]
mod tests;
