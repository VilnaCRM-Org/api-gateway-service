//! The `LogQL` and the request URL of a query of the audit lane (Story 14.3, FR-51, FR-54).
//!
//! A query uses only the fixed labels (`app`, `env`, `lane`, and `decision` and `upstream` when
//! the filter names them) in its stream selector and the structured metadata of the entry in its
//! label filters; it never filters on the text of a line.

use iam_domain::{AccessLogFilter, AccessLogRange};
use shared_domain::Uuid;

/// The path of the range query of Loki.
const QUERY_PATH: &str = "/loki/api/v1/query_range";

/// The decision values that a record has; an aggregate stands for many decisions and has none of
/// them, so the selector keeps aggregates out when no decision is named.
const RECORD_DECISIONS: &str = "allow|deny|error";

/// The value of the `lane` label of the audit lane.
const AUDIT_LANE: &str = "audit";

/// The values of the fixed labels of the entries of one environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Labels {
    /// The value of the `app` label.
    pub(super) app: String,
    /// The value of the `env` label.
    pub(super) env: String,
}

/// The `LogQL` of a search: the stream selector and the structured-metadata filters of `filter`.
pub(super) fn search_query(labels: &Labels, filter: &AccessLogFilter) -> String {
    let mut selector = vec![
        label("app", &labels.app),
        label("env", &labels.env),
        label("lane", AUDIT_LANE),
    ];
    selector.push(filter.decision.map_or_else(
        || format!("decision=~\"{RECORD_DECISIONS}\""),
        |decision| label("decision", decision.as_str()),
    ));
    if let Some(upstream) = &filter.upstream {
        selector.push(label("upstream", upstream));
    }
    let mut query = format!("{{{}}}", selector.join(","));
    let filters = [
        filter
            .subject_id
            .as_deref()
            .map(|id| ("subject_id", id.to_owned())),
        filter
            .subject_kind
            .map(|kind| ("subject_kind", kind.as_str().to_owned())),
        filter
            .reason
            .map(|reason| ("reason", reason.as_str().to_owned())),
        filter.route_id.map(|route| ("route_id", route.to_string())),
        filter.status.map(|status| ("status", status.to_string())),
    ];
    for (name, value) in filters.into_iter().flatten() {
        query.push_str(" | ");
        query.push_str(&label(name, &value));
    }
    query
}

/// The `LogQL` of the lookup of one decision: the selector of every decision and a filter on its
/// `decision_id` metadata.
pub(super) fn find_query(labels: &Labels, id: Uuid) -> String {
    let all = search_query(labels, &AccessLogFilter::default());
    format!("{all} | {}", label("decision_id", &id.to_string()))
}

/// `name="value"` with the value written as a `LogQL` string.
fn label(name: &str, value: &str) -> String {
    let mut text = String::with_capacity(value.len().saturating_add(name.len()).saturating_add(3));
    text.push_str(name);
    text.push_str("=\"");
    for character in value.chars() {
        match character {
            '\\' => text.push_str("\\\\"),
            '"' => text.push_str("\\\""),
            '\n' => text.push_str("\\n"),
            '\r' => text.push_str("\\r"),
            '\t' => text.push_str("\\t"),
            other => text.push(other),
        }
    }
    text.push('"');
    text
}

/// The URL of a range query: newest first, from the start of `range` to its end, at most `limit`
/// entries.
pub(super) fn query_url(base: &str, query: &str, range: AccessLogRange, limit: u32) -> String {
    format!(
        "{}{QUERY_PATH}?query={}&start={}&end={}&limit={limit}&direction=backward",
        base.trim_end_matches('/'),
        percent_encode(query),
        range.start_nanos(),
        range.until_nanos(),
    )
}

/// The URL of the ready endpoint of Loki.
pub(super) fn ready_url(base: &str) -> String {
    format!("{}/ready", base.trim_end_matches('/'))
}

/// `text` with every byte outside the unreserved characters of RFC 3986 written as `%XX`.
fn percent_encode(text: &str) -> String {
    let mut encoded = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(hex_digit(byte >> 4));
            encoded.push(hex_digit(byte & 0x0f));
        }
    }
    encoded
}

/// The upper-case hexadecimal digit of a nibble.
fn hex_digit(nibble: u8) -> char {
    char::from_digit(u32::from(nibble), 16).map_or('0', |digit| digit.to_ascii_uppercase())
}

#[cfg(test)]
mod tests;
