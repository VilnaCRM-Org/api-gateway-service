//! Port that reads the access decisions back from the log store (FR-51, FR-54).

use shared_domain::Uuid;

use crate::access_log_query::{AccessLogEntry, AccessLogQueryError, AccessLogSearch};

/// Reads the decisions of the audit lane from the log store.
///
/// A query that takes longer than the configured time fails with
/// [`AccessLogQueryError::Timeout`] and returns no partial page.
#[async_trait::async_trait]
pub trait AccessLogQuery: std::fmt::Debug + Send + Sync {
    /// The entries that meet `search`, newest first, at most `search.limit` of them, after the
    /// entries that `search.cursor` says were returned.
    ///
    /// # Errors
    ///
    /// [`AccessLogQueryError::Timeout`] when the query takes too long and
    /// [`AccessLogQueryError::Unavailable`] when the store cannot be reached or answers badly.
    async fn search(
        &self,
        search: &AccessLogSearch,
    ) -> Result<Vec<AccessLogEntry>, AccessLogQueryError>;

    /// The entry of the decision `id`, looked up in the window around the timestamp of its UUID
    /// v7; none when no entry is found there or `id` is not a UUID v7.
    ///
    /// # Errors
    ///
    /// The errors of [`AccessLogQuery::search`].
    async fn find(&self, id: Uuid) -> Result<Option<AccessLogEntry>, AccessLogQueryError>;

    /// Whether the log store is ready to answer queries.
    ///
    /// # Errors
    ///
    /// [`AccessLogQueryError::Timeout`] or [`AccessLogQueryError::Unavailable`] when it is not.
    async fn ready(&self) -> Result<(), AccessLogQueryError>;
}
