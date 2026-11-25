//! Values and doubles that the tests of the access decision reads share: the entries of a log
//! store and a store that answers like Loki does, newest first with a cursor.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessDecision, AccessLogCursor, AccessLogEntry, AccessLogQuery, AccessLogQueryError,
    AccessLogSearch, AccessRecord, CursorSeal, DecisionReason, SubjectKind,
};
use shared_domain::Uuid;

/// A seal that marks the payload with its own name; a token of another seal, or a plain payload,
/// does not open.
#[derive(Debug)]
pub(crate) struct NamedSeal(pub(crate) &'static str);

impl CursorSeal for NamedSeal {
    fn seal(&self, payload: &str) -> String {
        format!("{}:{payload}", self.0)
    }

    fn open(&self, token: &str) -> Option<String> {
        token
            .strip_prefix(self.0)
            .and_then(|rest| rest.strip_prefix(':'))
            .map(str::to_owned)
    }
}

/// The seal that the handlers of the tests use.
pub(crate) fn test_seal() -> Arc<dyn CursorSeal> {
    Arc::new(NamedSeal("test"))
}

/// The token that `cursor` has under [`test_seal`].
pub(crate) fn sealed(cursor: AccessLogCursor) -> String {
    cursor.sealed(&*test_seal())
}

/// The identifier of a decision: a UUID v7 whose last digits are `n`.
pub(crate) fn decision_id(n: u64) -> Uuid {
    Uuid::parse(&format!("0190f2a8-7b3c-7d4e-8f10-{n:012x}")).unwrap()
}

/// The entry of the decision `n` at `nanos` nanoseconds since 1970: a denial of a user.
pub(crate) fn entry(n: u64, nanos: u64) -> AccessLogEntry {
    AccessLogEntry {
        timestamp_nanos: nanos,
        record: AccessRecord {
            decision_id: decision_id(n),
            occurred_at: SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_nanos(nanos))
                .unwrap(),
            method: "GET".to_owned(),
            host: "api.example.test".to_owned(),
            route_id: None,
            route_template: Some("/api/users/{id}".to_owned()),
            status: 403,
            upstream: Some("user-service".to_owned()),
            latency_us: 1_200,
            bytes_in: 0,
            bytes_out: 64,
            request_id: Some("req-1".to_owned()),
            subject_id: Some("0190f2a8-7b3c-7d4e-8f10-1234567890ab".to_owned()),
            subject_kind: Some(SubjectKind::User),
            decision: AccessDecision::Deny,
            reason: DecisionReason::PermissionMissing,
            permission_key: Some("user:read".to_owned()),
            denied: vec!["user:read".to_owned()],
            project_id: None,
            policy_version: Some(7),
            credential_digest_prefix: Some("deadbeef".to_owned()),
        },
    }
}

/// A log store that holds entries, newest first, and applies the range, the cursor and the limit
/// of a search as the real store does; the filter is left to the store tests.
#[derive(Debug)]
pub(crate) struct FakeAccessLogQuery {
    entries: Vec<AccessLogEntry>,
    failure: Option<AccessLogQueryError>,
    searches: Mutex<Vec<AccessLogSearch>>,
}

impl FakeAccessLogQuery {
    /// A store that holds `entries`, which it sorts newest first.
    pub(crate) fn holding(mut entries: Vec<AccessLogEntry>) -> Self {
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.timestamp_nanos));
        Self {
            entries,
            failure: None,
            searches: Mutex::new(Vec::new()),
        }
    }

    /// A store that fails every call with `failure`.
    pub(crate) fn failing(failure: AccessLogQueryError) -> Self {
        Self {
            failure: Some(failure),
            ..Self::holding(Vec::new())
        }
    }

    /// The searches that reached the store.
    pub(crate) fn searches(&self) -> Vec<AccessLogSearch> {
        self.searches
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[async_trait::async_trait]
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
        let mut skip = search.cursor.map_or(0, |cursor| cursor.returned);
        let mut found = Vec::new();
        for entry in &self.entries {
            let at = entry.timestamp_nanos;
            let kept = at >= search.range.start_nanos()
                && at < search.range.until_nanos()
                && search
                    .cursor
                    .is_none_or(|cursor| at <= cursor.timestamp_nanos);
            let skipped = search
                .cursor
                .is_some_and(|cursor| at == cursor.timestamp_nanos)
                && skip > 0;
            if skipped {
                skip = skip.saturating_sub(1);
            } else if kept && found.len() < usize::try_from(search.limit).unwrap() {
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

#[cfg(test)]
mod tests;
