//! Store of expired revocation records of the IAM context, as a double.

use std::sync::{Mutex, PoisonError};
use std::time::SystemTime;

use async_trait::async_trait;
use iam_domain::{ExpiredRevocation, ExpiredRevocationStore, RepositoryError};

/// A store that holds revocation records in memory and answers with the rule of the port: the
/// records whose prune-after instant is strictly before the asked instant, oldest first, at most
/// the limit.
#[derive(Debug)]
pub struct FakeExpiredRevocationStore {
    records: Vec<ExpiredRevocation>,
    failing: bool,
    requests: Mutex<Vec<(SystemTime, u32)>>,
}

impl FakeExpiredRevocationStore {
    /// A store without records.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
            failing: false,
            requests: Mutex::new(Vec::new()),
        }
    }

    /// The same store holding `records`, expired or not.
    #[must_use]
    pub fn holding(mut self, records: Vec<ExpiredRevocation>) -> Self {
        self.records = records;
        self
    }

    /// A store that answers `Unavailable` to every request.
    #[must_use]
    pub const fn failing() -> Self {
        Self {
            records: Vec::new(),
            failing: true,
            requests: Mutex::new(Vec::new()),
        }
    }

    /// The `(now, limit)` of every request, in order.
    #[must_use]
    pub fn requests(&self) -> Vec<(SystemTime, u32)> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Default for FakeExpiredRevocationStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ExpiredRevocationStore for FakeExpiredRevocationStore {
    async fn expired_revocations(
        &self,
        now: SystemTime,
        limit: u32,
    ) -> Result<Vec<ExpiredRevocation>, RepositoryError> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((now, limit));
        if self.failing {
            return Err(RepositoryError::Unavailable(
                "in-memory expired revocation store failure".into(),
            ));
        }
        let mut expired: Vec<ExpiredRevocation> = self
            .records
            .iter()
            .filter(|record| record.prune_after() < now)
            .cloned()
            .collect();
        expired.sort_by_key(ExpiredRevocation::prune_after);
        expired.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(expired)
    }
}

#[cfg(test)]
mod tests;
