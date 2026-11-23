//! Startup lock double of the IAM context.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use iam_domain::{LockGuard, RepositoryError, StartupLock};

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The names of the locks that are held and that were taken, shared with the guards.
#[derive(Debug, Default)]
struct Book {
    held: Vec<String>,
    taken: Vec<String>,
}

/// A held lock of the double; dropping it releases the name.
#[derive(Debug)]
struct FakeGuard {
    name: String,
    book: Arc<Mutex<Book>>,
}

impl LockGuard for FakeGuard {}

impl Drop for FakeGuard {
    fn drop(&mut self) {
        let mut book = locked(&self.book);
        if let Some(position) = book.held.iter().position(|held| *held == self.name) {
            book.held.remove(position);
        }
    }
}

/// A lock that never blocks and records which names were taken and which are held now.
#[derive(Debug, Default)]
pub struct FakeStartupLock {
    book: Arc<Mutex<Book>>,
    failing: bool,
}

impl FakeStartupLock {
    /// A lock with nothing held.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A lock whose storage is unavailable: every acquisition fails.
    #[must_use]
    pub fn failing() -> Self {
        Self {
            failing: true,
            ..Self::default()
        }
    }

    /// The names that were taken, in order, released or not.
    #[must_use]
    pub fn taken(&self) -> Vec<String> {
        locked(&self.book).taken.clone()
    }

    /// The names that are held now.
    #[must_use]
    pub fn held(&self) -> Vec<String> {
        locked(&self.book).held.clone()
    }
}

#[async_trait]
impl StartupLock for FakeStartupLock {
    async fn acquire(&self, name: &str) -> Result<Box<dyn LockGuard>, RepositoryError> {
        if self.failing {
            return Err(RepositoryError::Unavailable(
                "the lock storage is down".into(),
            ));
        }
        let mut book = locked(&self.book);
        book.held.push(name.to_owned());
        book.taken.push(name.to_owned());
        drop(book);
        Ok(Box::new(FakeGuard {
            name: name.to_owned(),
            book: Arc::clone(&self.book),
        }))
    }
}

#[cfg(test)]
mod tests;
