//! The answer of a Loki range query read into access log entries (Story 14.3).
//!
//! Loki answers with streams of `[timestamp, line]` pairs, each stream newest first. The line of
//! an entry is the JSON of the decision that the audit sink pushed, so the entry is read from it
//! and not from the metadata, which Loki may or may not repeat as labels. An entry that is not a
//! decision of the gateway makes the whole answer unusable: a record that cannot be read is never
//! dropped silently.

use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessDecision, AccessLogEntry, AccessLogQueryError, AccessRecord, DecisionReason, SubjectKind,
};
use serde::Deserialize;
use serde_json::Value;
use shared_domain::Uuid;

/// The envelope of the answer of a range query.
#[derive(Debug, Deserialize)]
struct Envelope {
    status: String,
    data: Data,
}

/// The data of the answer.
#[derive(Debug, Deserialize)]
struct Data {
    result: Vec<Stream>,
}

/// One stream of the result: its entries, each a timestamp, a line and perhaps metadata.
#[derive(Debug, Deserialize)]
struct Stream {
    values: Vec<Vec<Value>>,
}

/// The JSON line of a decision, as `render_entry` writes it.
#[derive(Debug, Deserialize)]
struct Line {
    kind: String,
    decision_id: String,
    occurred_at: u64,
    method: String,
    host: String,
    route_id: Option<String>,
    route_template: Option<String>,
    status: u16,
    upstream: Option<String>,
    latency_us: u64,
    bytes_in: u64,
    bytes_out: u64,
    request_id: Option<String>,
    subject_id: Option<String>,
    subject_kind: Option<String>,
    decision: String,
    reason: String,
    permission_key: Option<String>,
    denied: Vec<String>,
    project_id: Option<String>,
    policy_version: Option<i64>,
    credential_digest_prefix: Option<String>,
}

/// The entries of `body`, newest first; entries of equal timestamps keep the order of Loki.
///
/// # Errors
///
/// [`AccessLogQueryError::Unavailable`] when the body is not the answer of a successful query or
/// an entry of it is not a decision.
pub(super) fn entries_of(body: &[u8]) -> Result<Vec<AccessLogEntry>, AccessLogQueryError> {
    let envelope: Envelope =
        serde_json::from_slice(body).map_err(|_error| AccessLogQueryError::Unavailable)?;
    if envelope.status != "success" {
        return Err(AccessLogQueryError::Unavailable);
    }
    let mut entries = Vec::new();
    for stream in envelope.data.result {
        for value in &stream.values {
            entries.push(entry_of(value)?);
        }
    }
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.timestamp_nanos));
    Ok(entries)
}

/// The entry of one `[timestamp, line, ...]` value.
fn entry_of(value: &[Value]) -> Result<AccessLogEntry, AccessLogQueryError> {
    let unusable = || AccessLogQueryError::Unavailable;
    let timestamp = value
        .first()
        .and_then(Value::as_str)
        .and_then(|text| text.parse::<u64>().ok())
        .ok_or_else(unusable)?;
    let line = value.get(1).and_then(Value::as_str).ok_or_else(unusable)?;
    let line: Line = serde_json::from_str(line).map_err(|_error| unusable())?;
    if line.kind != "record" {
        return Err(unusable());
    }
    Ok(AccessLogEntry {
        timestamp_nanos: timestamp,
        record: record_of(line).ok_or_else(unusable)?,
    })
}

/// The record of a line; none when a value of it is not one that the gateway writes.
fn record_of(line: Line) -> Option<AccessRecord> {
    Some(AccessRecord {
        decision_id: Uuid::parse(&line.decision_id).ok()?,
        occurred_at: SystemTime::UNIX_EPOCH.checked_add(Duration::from_micros(line.occurred_at))?,
        method: line.method,
        host: line.host,
        route_id: line.route_id.as_deref().map(Uuid::parse).transpose().ok()?,
        route_template: line.route_template,
        status: line.status,
        upstream: line.upstream,
        latency_us: line.latency_us,
        bytes_in: line.bytes_in,
        bytes_out: line.bytes_out,
        request_id: line.request_id,
        subject_id: line.subject_id,
        subject_kind: line
            .subject_kind
            .as_deref()
            .map(SubjectKind::parse)
            .transpose()
            .ok()?,
        decision: AccessDecision::parse(&line.decision)?,
        reason: DecisionReason::parse(&line.reason)?,
        permission_key: line.permission_key,
        denied: line.denied,
        project_id: line
            .project_id
            .as_deref()
            .map(Uuid::parse)
            .transpose()
            .ok()?,
        policy_version: line.policy_version,
        credential_digest_prefix: line.credential_digest_prefix,
    })
}

#[cfg(test)]
mod tests;
