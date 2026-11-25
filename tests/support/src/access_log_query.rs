//! Access log store double of the IAM context.

use std::sync::{Mutex, PoisonError};

use async_trait::async_trait;
use iam_domain::{AccessLogEntry, AccessLogQuery, AccessLogQueryError, AccessLogSearch};
use shared_domain::Uuid;

/// A log store that holds entries, newest first, and answers as the real store does: the range,
/// the cursor and the limit of a search are applied, the filter is not.
///
/// It can be made to fail every call with a given error, and it keeps the searches it received.
#[derive(Debug, Default)]
pub struct FakeAccessLogQuery {
    entries: Vec<AccessLogEntry>,
    failure: Option<AccessLogQueryError>,
    searches: Mutex<Vec<AccessLogSearch>>,
}

impl FakeAccessLogQuery {
    /// A store that holds nothing and answers every call.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A store that holds `entries`, which it sorts newest first.
    #[must_use]
    pub fn holding(mut entries: Vec<AccessLogEntry>) -> Self {
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.timestamp_nanos));
        Self {
            entries,
            ..Self::default()
        }
    }

    /// A store that fails every call with `failure`.
    #[must_use]
    pub fn failing(failure: AccessLogQueryError) -> Self {
        Self {
            failure: Some(failure),
            ..Self::default()
        }
    }

    /// The searches that reached the store, oldest first.
    #[must_use]
    pub fn searches(&self) -> Vec<AccessLogSearch> {
        self.searches
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[async_trait]
impl AccessLogQuery for FakeAccessLogQuery {
    async fn search(
        &self,
        search: &AccessLogSearch,
    ) -> Result<Vec<AccessLogEntry>, AccessLogQueryError> {
        self.searches
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(search.clone());
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        let limit = usize::try_from(search.limit).unwrap_or(usize::MAX);
        let mut skip = search.cursor.map_or(0, |cursor| cursor.returned);
        let mut found = Vec::new();
        for entry in &self.entries {
            let at = entry.timestamp_nanos;
            if search
                .cursor
                .is_some_and(|cursor| at > cursor.timestamp_nanos)
            {
                continue;
            }
            let returned = skip > 0
                && search
                    .cursor
                    .is_some_and(|cursor| at == cursor.timestamp_nanos);
            if returned {
                skip = skip.saturating_sub(1);
                continue;
            }
            let within = at >= search.range.start_nanos() && at < search.range.until_nanos();
            if within && found.len() < limit {
                found.push(entry.clone());
            }
        }
        Ok(found)
    }

    async fn find(&self, id: Uuid) -> Result<Option<AccessLogEntry>, AccessLogQueryError> {
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        Ok(self
            .entries
            .iter()
            .find(|entry| entry.record.decision_id == id)
            .cloned())
    }

    async fn ready(&self) -> Result<(), AccessLogQueryError> {
        self.failure.map_or(Ok(()), Err)
    }
}
