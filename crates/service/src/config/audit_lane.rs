//! The settings of the audit lane of the access log (Story 14.2, FR-50, NFR-24):
//! `LOKI_PUSH_URL`, `LOKI_TENANT_ID`, `ACCESS_LOG_AUDIT_FLUSH_INTERVAL` and
//! `ACCESS_LOG_AUDIT_MAX_PENDING`.

use std::time::Duration;

use axum::http::Uri;

use super::{
    AccessLogSettings, AppEnv, Collector, GatewayArgs, Parsed, RateLimitSettings,
    access_log_settings, positive_duration, rate_limit_settings,
};

/// The push URL of a `dev` or `test` configuration that does not set `LOKI_PUSH_URL`: the Loki of
/// the compose stack.
pub const DEFAULT_LOKI_PUSH_URL: &str = "http://localhost:3100/loki/api/v1/push";

/// The tenant of a configuration that does not set `LOKI_TENANT_ID`.
pub const DEFAULT_LOKI_TENANT_ID: &str = "iam";

/// The flush interval of a configuration that does not set `ACCESS_LOG_AUDIT_FLUSH_INTERVAL`.
const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_secs(1);

/// The longest accepted `ACCESS_LOG_AUDIT_FLUSH_INTERVAL`.
const MAX_FLUSH_INTERVAL: Duration = Duration::from_mins(1);

/// The `ACCESS_LOG_AUDIT_MAX_PENDING` of a configuration that does not set it.
pub const DEFAULT_MAX_PENDING: Duration = Duration::from_secs(5);

/// The longest accepted `ACCESS_LOG_AUDIT_MAX_PENDING`.
const MAX_MAX_PENDING: Duration = Duration::from_mins(10);

/// The value of the `env` label of the audit lane: the deployment environment.
#[must_use]
pub const fn env_label(app_env: AppEnv) -> &'static str {
    match app_env {
        AppEnv::Dev => "dev",
        AppEnv::Test => "test",
        AppEnv::Prod => "prod",
    }
}

/// How the audit lane of the access log reaches Loki and when it stops admitting audited requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLaneSettings {
    /// `LOKI_PUSH_URL`: the push endpoint of Loki, a plain `http://` URL.
    pub push_url: Uri,
    /// `LOKI_TENANT_ID`: the value of the `X-Scope-OrgID` header of a push.
    pub tenant_id: String,
    /// `ACCESS_LOG_AUDIT_FLUSH_INTERVAL`: how often the queued audit entries are pushed.
    pub flush_interval: Duration,
    /// `ACCESS_LOG_AUDIT_MAX_PENDING`: how long the oldest audit entry may wait for Loki's
    /// acknowledgement before audit-required requests are refused.
    pub max_pending: Duration,
}

/// The settings that bound what the gateway logs and counts: the access log, the shared rate counters
/// and the audit lane, read in the order of the configuration table.
pub(super) fn lane_bounds(
    collector: &mut Collector,
    args: &GatewayArgs,
    app_env: Option<AppEnv>,
) -> (
    Option<AccessLogSettings>,
    Option<RateLimitSettings>,
    Option<AuditLaneSettings>,
) {
    let access_log = access_log_settings(collector, args);
    let audit_lane = audit_lane_settings(collector, args, app_env);
    let rate_limit = rate_limit_settings(collector, args);
    (access_log, rate_limit, audit_lane)
}

/// `LOKI_PUSH_URL` (required outside `dev` and `test`), `LOKI_TENANT_ID` (default `iam`),
/// `ACCESS_LOG_AUDIT_FLUSH_INTERVAL` (default `1s`) and `ACCESS_LOG_AUDIT_MAX_PENDING` (default
/// `5s`, longer than the flush interval).
///
/// `None` when a problem was reported.
pub(super) fn audit_lane_settings(
    collector: &mut Collector,
    args: &GatewayArgs,
    app_env: Option<AppEnv>,
) -> Option<AuditLaneSettings> {
    let push_url = push_url(collector, args.loki_push_url.as_deref(), app_env);
    let tenant = collector.collect(
        "LOKI_TENANT_ID",
        tenant_id(args.service.access_log_query.loki_tenant_id.as_deref()),
    );
    let flush = collector.collect(
        "ACCESS_LOG_AUDIT_FLUSH_INTERVAL",
        bounded_duration(
            args.access_log_audit_flush_interval.as_deref(),
            DEFAULT_FLUSH_INTERVAL,
            MAX_FLUSH_INTERVAL,
        ),
    );
    let pending = collector.collect(
        "ACCESS_LOG_AUDIT_MAX_PENDING",
        bounded_duration(
            args.access_log_audit_max_pending.as_deref(),
            DEFAULT_MAX_PENDING,
            MAX_MAX_PENDING,
        ),
    );
    let (flush_interval, max_pending) = (flush?, pending?);
    if max_pending <= flush_interval {
        return collector.reject(
            "ACCESS_LOG_AUDIT_MAX_PENDING",
            "must be longer than ACCESS_LOG_AUDIT_FLUSH_INTERVAL",
        );
    }
    Some(AuditLaneSettings {
        push_url: push_url?,
        tenant_id: tenant?,
        flush_interval,
        max_pending,
    })
}

/// `LOKI_PUSH_URL`: a plain `http://` URL with a host; unset it is the compose Loki in `dev` and
/// `test`, and a problem elsewhere.
fn push_url(collector: &mut Collector, raw: Option<&str>, app_env: Option<AppEnv>) -> Option<Uri> {
    match (raw, app_env?) {
        (Some(raw), _) => collector.collect("LOKI_PUSH_URL", parse_push_url(raw)),
        (None, AppEnv::Dev | AppEnv::Test) => {
            collector.collect("LOKI_PUSH_URL", parse_push_url(DEFAULT_LOKI_PUSH_URL))
        }
        (None, AppEnv::Prod) => {
            collector.reject("LOKI_PUSH_URL", "is required outside APP_ENV dev and test")
        }
    }
}

/// The reason of a push URL that cannot be used.
const PUSH_URL_REASON: &str =
    "must be an http:// URL with a host, such as http://loki:3100/loki/api/v1/push";

fn parse_push_url(raw: &str) -> Parsed<Uri> {
    let uri: Uri = raw.parse().map_err(|_error| PUSH_URL_REASON.to_owned())?;
    let plain = uri.scheme_str() == Some("http");
    let hosted = uri.host().is_some_and(|host| !host.is_empty());
    if plain && hosted && uri.query().is_none() {
        Ok(uri)
    } else {
        Err(PUSH_URL_REASON.to_owned())
    }
}

/// `LOKI_TENANT_ID`: a non-empty value without whitespace or control characters, so that it is a
/// valid header value.
pub(super) fn tenant_id(raw: Option<&str>) -> Parsed<String> {
    let value = raw.unwrap_or(DEFAULT_LOKI_TENANT_ID);
    let valid = !value.is_empty()
        && value.len() <= 150
        && value.bytes().all(|byte| byte.is_ascii_graphic());
    if valid {
        Ok(value.to_owned())
    } else {
        Err("must be 1 to 150 visible ASCII characters".to_owned())
    }
}

/// A positive duration that is at most `max`.
pub(super) fn bounded_duration(
    raw: Option<&str>,
    default: Duration,
    max: Duration,
) -> Parsed<Duration> {
    let value = positive_duration(raw, default)
        .map_err(|_reason| "must be a positive duration such as 500ms, 2s or 1m".to_owned())?;
    if value <= max {
        Ok(value)
    } else {
        Err(format!(
            "must be at most {}",
            humantime::format_duration(max)
        ))
    }
}
