//! The settings of the access decision queries (Story 14.3, FR-51, FR-54, NFR-44):
//! `LOKI_QUERY_URL`, `LOKI_TENANT_ID`, `ACCESS_LOG_QUERY_MAX_RANGE`, `ACCESS_LOG_QUERY_TIMEOUT` and
//! `ACCESS_LOG_CURSOR_KEY`.

use std::time::Duration;

use axum::http::Uri;

use super::audit_lane::{bounded_duration, tenant_id};
use super::{AppEnv, Collector, Parsed, ServeArgs};

/// The query URL of a `dev` or `test` configuration that does not set `LOKI_QUERY_URL`: the Loki
/// of the compose stack.
pub const DEFAULT_LOKI_QUERY_URL: &str = "http://localhost:3100";

/// The `ACCESS_LOG_QUERY_MAX_RANGE` of a configuration that does not set it.
pub const DEFAULT_MAX_RANGE: Duration = Duration::from_hours(24);

/// The longest accepted `ACCESS_LOG_QUERY_MAX_RANGE`.
const MAX_MAX_RANGE: Duration = Duration::from_hours(168);

/// The `ACCESS_LOG_QUERY_TIMEOUT` of a configuration that does not set it.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// The longest accepted `ACCESS_LOG_QUERY_TIMEOUT`.
const MAX_TIMEOUT: Duration = Duration::from_mins(2);

/// The shortest accepted `ACCESS_LOG_CURSOR_KEY`, in bytes: the size of an HMAC-SHA256 key.
pub const MIN_CURSOR_KEY_BYTES: usize = 32;

/// The longest accepted `ACCESS_LOG_CURSOR_KEY`, in bytes.
const MAX_CURSOR_KEY_BYTES: usize = 256;

/// The key that seals the cursors; its debug form never shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct CursorKey(Vec<u8>);

impl CursorKey {
    /// The bytes of the key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for CursorKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CursorKey(<redacted>)")
    }
}

/// How the control plane reaches Loki to read access decisions and what bounds a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessLogQuerySettings {
    /// `LOKI_QUERY_URL`: the base URL of Loki, a plain `http://` URL.
    pub query_url: Uri,
    /// `LOKI_TENANT_ID`: the value of the `X-Scope-OrgID` header of a query.
    pub tenant_id: String,
    /// `ACCESS_LOG_QUERY_MAX_RANGE`: the longest time range of one query.
    pub max_range: Duration,
    /// `ACCESS_LOG_QUERY_TIMEOUT`: how long a query may take before it fails with 504.
    pub timeout: Duration,
    /// `ACCESS_LOG_CURSOR_KEY`: the key that seals the cursors; none means a random key that lives
    /// as long as the process.
    pub cursor_key: Option<CursorKey>,
}

/// `LOKI_QUERY_URL` (required outside `dev` and `test`), `LOKI_TENANT_ID` (default `iam`),
/// `ACCESS_LOG_QUERY_MAX_RANGE` (default `24h`, at most 7 days), `ACCESS_LOG_QUERY_TIMEOUT`
/// (default `5s`, at most 2 minutes) and `ACCESS_LOG_CURSOR_KEY` (optional, 32 to 256 characters).
///
/// `None` when a problem was reported.
pub(super) fn access_log_query_settings(
    collector: &mut Collector,
    args: &ServeArgs,
    app_env: Option<AppEnv>,
) -> Option<AccessLogQuerySettings> {
    let raw = &args.access_log_query;
    let query_url = query_url(collector, raw.loki_query_url.as_deref(), app_env);
    let tenant = collector.collect("LOKI_TENANT_ID", tenant_id(raw.loki_tenant_id.as_deref()));
    let max_range = collector.collect(
        "ACCESS_LOG_QUERY_MAX_RANGE",
        bounded_duration(raw.max_range.as_deref(), DEFAULT_MAX_RANGE, MAX_MAX_RANGE),
    );
    let timeout = collector.collect(
        "ACCESS_LOG_QUERY_TIMEOUT",
        bounded_duration(raw.timeout.as_deref(), DEFAULT_TIMEOUT, MAX_TIMEOUT),
    );
    let cursor_key = collector.collect(
        "ACCESS_LOG_CURSOR_KEY",
        cursor_key(raw.cursor_key.as_deref()),
    );
    Some(AccessLogQuerySettings {
        query_url: query_url?,
        tenant_id: tenant?,
        max_range: max_range?,
        timeout: timeout?,
        cursor_key: cursor_key?,
    })
}

/// `ACCESS_LOG_CURSOR_KEY`: unset it is none; set it must be 32 to 256 characters.
fn cursor_key(raw: Option<&str>) -> Parsed<Option<CursorKey>> {
    raw.map(|raw| {
        if (MIN_CURSOR_KEY_BYTES..=MAX_CURSOR_KEY_BYTES).contains(&raw.len()) {
            Ok(CursorKey(raw.as_bytes().to_vec()))
        } else {
            Err(format!(
                "must be {MIN_CURSOR_KEY_BYTES} to {MAX_CURSOR_KEY_BYTES} characters"
            ))
        }
    })
    .transpose()
}

/// `LOKI_QUERY_URL`: a plain `http://` URL with a host and no path; unset it is the compose Loki
/// in `dev` and `test`, and a problem elsewhere.
fn query_url(collector: &mut Collector, raw: Option<&str>, app_env: Option<AppEnv>) -> Option<Uri> {
    match (raw, app_env?) {
        (Some(raw), _) => collector.collect("LOKI_QUERY_URL", parse_query_url(raw)),
        (None, AppEnv::Dev | AppEnv::Test) => {
            collector.collect("LOKI_QUERY_URL", parse_query_url(DEFAULT_LOKI_QUERY_URL))
        }
        (None, AppEnv::Prod) => {
            collector.reject("LOKI_QUERY_URL", "is required outside APP_ENV dev and test")
        }
    }
}

/// The reason of a query URL that cannot be used.
const QUERY_URL_REASON: &str =
    "must be an http:// URL with a host and no path, such as http://loki:3100";

fn parse_query_url(raw: &str) -> Parsed<Uri> {
    let uri: Uri = raw.parse().map_err(|_error| QUERY_URL_REASON.to_owned())?;
    let plain = uri.scheme_str() == Some("http");
    let hosted = uri.host().is_some_and(|host| !host.is_empty());
    let bare = matches!(uri.path(), "" | "/") && uri.query().is_none();
    if plain && hosted && bare {
        Ok(uri)
    } else {
        Err(QUERY_URL_REASON.to_owned())
    }
}
