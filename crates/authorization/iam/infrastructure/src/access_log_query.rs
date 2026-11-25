//! The adapter that reads access decisions back from Loki (Story 14.3, FR-51, FR-54, NFR-44).
//!
//! [`LokiAccessLogQuery`] builds the `LogQL` of a search from the fixed labels and the structured
//! metadata filters, asks a [`LokiQueryTransport`] for it and reads the entries out of the answer.
//! The transport owns the network, the tenant header and the time a query may take; this adapter
//! owns what is asked and how the answer is understood. A page is never partial: an answer that
//! cannot be read in full is an error.

use std::sync::Arc;

use iam_domain::{
    AccessLogEntry, AccessLogQuery, AccessLogQueryError, AccessLogRange, AccessLogSearch,
    MAX_CURSOR_RETURNED, MAX_LOG_READ,
};
use shared_domain::Uuid;

use self::answer::entries_of;
use self::logql::{Labels, find_query, query_url, ready_url, search_query};

mod answer;
mod logql;

/// What Loki answered to a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LokiResponse {
    /// The HTTP status of the answer.
    pub status: u16,
    /// The body of the answer.
    pub body: Vec<u8>,
}

/// Sends one request to Loki; the part of the adapter that touches the network.
///
/// The implementation adds the tenant header, bounds the whole call (connection, answer and body)
/// by `ACCESS_LOG_QUERY_TIMEOUT` and tells a call that took too long from one that could not be
/// made.
#[async_trait::async_trait]
pub trait LokiQueryTransport: std::fmt::Debug + Send + Sync {
    /// Gets `url`.
    ///
    /// # Errors
    ///
    /// [`AccessLogQueryError::Timeout`] when the call takes longer than the query timeout and
    /// [`AccessLogQueryError::Unavailable`] when the connection is refused or breaks.
    async fn get(&self, url: &str) -> Result<LokiResponse, AccessLogQueryError>;
}

/// Reads the decisions of the audit lane from Loki.
#[derive(Debug)]
pub struct LokiAccessLogQuery {
    transport: Arc<dyn LokiQueryTransport>,
    base: String,
    labels: Labels,
}

impl LokiAccessLogQuery {
    /// An adapter that queries the Loki at `base` (a URL such as `http://loki:3100`) for the
    /// entries labelled `app` and `env`, through `transport`.
    #[must_use]
    pub fn new(transport: Arc<dyn LokiQueryTransport>, base: &str, app: &str, env: &str) -> Self {
        Self {
            transport,
            base: base.to_owned(),
            labels: Labels {
                app: app.to_owned(),
                env: env.to_owned(),
            },
        }
    }

    /// The entries that the range query `query` finds, at most `limit`, newest first.
    async fn query(
        &self,
        query: &str,
        range: AccessLogRange,
        limit: u32,
    ) -> Result<Vec<AccessLogEntry>, AccessLogQueryError> {
        let response = self
            .transport
            .get(&query_url(&self.base, query, range, limit))
            .await?;
        answered(&response)?;
        entries_of(&response.body)
    }

    async fn search_entries(
        &self,
        search: &AccessLogSearch,
    ) -> Result<Vec<AccessLogEntry>, AccessLogQueryError> {
        let skip = search
            .cursor
            .map_or(0, |cursor| cursor.returned.min(MAX_CURSOR_RETURNED));
        let range = search.cursor.map_or(search.range, |cursor| {
            search.range.ending_at(cursor.timestamp_nanos)
        });
        let query = search_query(&self.labels, &search.filter);
        let mut entries = self
            .query(
                &query,
                range,
                search.limit.saturating_add(skip).min(MAX_LOG_READ),
            )
            .await?;
        if let Some(cursor) = search.cursor {
            drop_returned(&mut entries, cursor.timestamp_nanos, skip);
        }
        entries.truncate(usize::try_from(search.limit).unwrap_or(usize::MAX));
        Ok(entries)
    }

    async fn find_entry(&self, id: Uuid) -> Result<Option<AccessLogEntry>, AccessLogQueryError> {
        let Some(range) = AccessLogRange::around(id) else {
            return Ok(None);
        };
        let entries = self.query(&find_query(&self.labels, id), range, 1).await?;
        Ok(entries
            .into_iter()
            .find(|entry| entry.record.decision_id == id))
    }

    async fn probe(&self) -> Result<(), AccessLogQueryError> {
        let response = self.transport.get(&ready_url(&self.base)).await?;
        answered(&response)
    }
}

/// Removes the first `skip` entries at `timestamp_nanos`, which earlier pages returned.
fn drop_returned(entries: &mut Vec<AccessLogEntry>, timestamp_nanos: u64, skip: u32) {
    let mut left = skip;
    entries.retain(|entry| {
        let returned = left > 0 && entry.timestamp_nanos == timestamp_nanos;
        if returned {
            left = left.saturating_sub(1);
        }
        !returned
    });
}

/// Whether Loki answered with a success status; a 504 is a query that took too long inside Loki.
const fn answered(response: &LokiResponse) -> Result<(), AccessLogQueryError> {
    match response.status {
        200..=299 => Ok(()),
        504 => Err(AccessLogQueryError::Timeout),
        _ => Err(AccessLogQueryError::Unavailable),
    }
}

#[async_trait::async_trait]
impl AccessLogQuery for LokiAccessLogQuery {
    async fn search(
        &self,
        search: &AccessLogSearch,
    ) -> Result<Vec<AccessLogEntry>, AccessLogQueryError> {
        self.search_entries(search).await
    }

    async fn find(&self, id: Uuid) -> Result<Option<AccessLogEntry>, AccessLogQueryError> {
        self.find_entry(id).await
    }

    async fn ready(&self) -> Result<(), AccessLogQueryError> {
        self.probe().await
    }
}

#[cfg(test)]
mod tests;
