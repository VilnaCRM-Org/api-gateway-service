//! Token lifetime floor double of the IAM context.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use iam_domain::{RepositoryError, TokenLifetimeFloor};

/// A floor that keeps the longest lifetime it was raised to in memory, with the rules of the
/// PostgreSQL adapter: a lower value never lowers it.
#[derive(Debug, Default)]
pub struct FakeTokenLifetimeFloor {
    stored: Mutex<Option<Duration>>,
    failing: AtomicBool,
}

impl FakeTokenLifetimeFloor {
    /// A floor that holds no value yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A floor that already holds `lifetime`.
    #[must_use]
    pub const fn holding(lifetime: Duration) -> Self {
        Self {
            stored: Mutex::new(Some(lifetime)),
            failing: AtomicBool::new(false),
        }
    }

    /// Makes every later call answer `Unavailable`, or answer normally again.
    pub fn fail(&self, failing: bool) {
        self.failing.store(failing, Ordering::Release);
    }

    fn check(&self) -> Result<(), RepositoryError> {
        if self.failing.load(Ordering::Acquire) {
            Err(RepositoryError::Unavailable(
                "in-memory floor failure".into(),
            ))
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl TokenLifetimeFloor for FakeTokenLifetimeFloor {
    async fn raise_to(&self, configured: Duration) -> Result<Duration, RepositoryError> {
        self.check()?;
        let mut stored = self.stored.lock().unwrap_or_else(PoisonError::into_inner);
        let floor = stored.map_or(configured, |held| held.max(configured));
        *stored = Some(floor);
        drop(stored);
        Ok(floor)
    }

    async fn longest(&self) -> Result<Option<Duration>, RepositoryError> {
        self.check()?;
        Ok(*self.stored.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

#[cfg(test)]
mod tests;
