//! The sink of the ordinary lane: JSON lines on stdout, tailed by Grafana Alloy (FR-50).

use std::io::{Stdout, Write};
use std::sync::{Mutex, PoisonError};
use std::time::SystemTime;

use iam_domain::{AccessAggregate, AccessEntry, AccessLane, AccessLogSink, AccessRecord};
use serde_json::{Map, Value, json};

/// Writes every entry as one line of JSON to its writer, stdout by default.
///
/// In production it takes the ordinary lane only: the audit lane goes to the Loki push sink of
/// Story 14.2, so no audit-lane entry is written to stdout. A write that fails is logged and the
/// entry is lost: the access log never delays or changes a decision.
#[derive(Debug)]
pub struct StdoutAccessLogSink<W: Write + Send + std::fmt::Debug = Stdout> {
    writer: Mutex<W>,
}

impl StdoutAccessLogSink {
    /// A sink that writes to the standard output of the process.
    #[must_use]
    pub fn new() -> Self {
        Self::to_writer(std::io::stdout())
    }
}

impl Default for StdoutAccessLogSink {
    fn default() -> Self {
        Self::new()
    }
}

impl<W: Write + Send + std::fmt::Debug> StdoutAccessLogSink<W> {
    /// A sink that writes to `writer`.
    #[must_use]
    pub const fn to_writer(writer: W) -> Self {
        Self {
            writer: Mutex::new(writer),
        }
    }

    /// Writes `bytes` to the writer under its lock.
    fn append(&self, bytes: &[u8]) -> std::io::Result<()> {
        self.writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .write_all(bytes)
    }
}

impl<W: Write + Send + std::fmt::Debug> AccessLogSink for StdoutAccessLogSink<W> {
    fn write(&self, lane: AccessLane, entry: &AccessEntry) {
        let mut rendered = render_entry(lane, entry);
        rendered.push('\n');
        if let Err(error) = self.append(rendered.as_bytes()) {
            log_not_written(&error);
        }
    }
}

fn log_not_written(error: &std::io::Error) {
    tracing::warn!(error = %error, "an access log entry could not be written");
}

/// The JSON line of `entry`, without the line break.
#[must_use]
pub fn render_entry(lane: AccessLane, entry: &AccessEntry) -> String {
    let value = match entry {
        AccessEntry::Record(record) => record_json(lane, record),
        AccessEntry::Aggregate(aggregate) => aggregate_json(lane, aggregate),
    };
    value.to_string()
}

fn record_json(lane: AccessLane, record: &AccessRecord) -> Value {
    let mut fields = Map::new();
    fields.insert("kind".to_owned(), json!("record"));
    fields.insert("lane".to_owned(), json!(lane.as_str()));
    fields.insert(
        "decision_id".to_owned(),
        json!(record.decision_id.to_string()),
    );
    fields.insert(
        "occurred_at".to_owned(),
        json!(unix_micros(record.occurred_at)),
    );
    fields.insert("method".to_owned(), json!(record.method));
    fields.insert("host".to_owned(), json!(record.host));
    fields.insert(
        "route_id".to_owned(),
        json!(record.route_id.map(|id| id.to_string())),
    );
    fields.insert("route_template".to_owned(), json!(record.route_template));
    fields.insert("status".to_owned(), json!(record.status));
    fields.insert("upstream".to_owned(), json!(record.upstream));
    fields.insert("latency_us".to_owned(), json!(record.latency_us));
    fields.insert("bytes_in".to_owned(), json!(record.bytes_in));
    fields.insert("bytes_out".to_owned(), json!(record.bytes_out));
    fields.insert("request_id".to_owned(), json!(record.request_id));
    fields.insert("subject_id".to_owned(), json!(record.subject_id));
    fields.insert(
        "subject_kind".to_owned(),
        json!(record.subject_kind.map(iam_domain::SubjectKind::as_str)),
    );
    fields.insert("decision".to_owned(), json!(record.decision.as_str()));
    fields.insert("reason".to_owned(), json!(record.reason.as_str()));
    fields.insert("permission_key".to_owned(), json!(record.permission_key));
    fields.insert("denied".to_owned(), json!(record.denied));
    fields.insert(
        "project_id".to_owned(),
        json!(record.project_id.map(|id| id.to_string())),
    );
    fields.insert("policy_version".to_owned(), json!(record.policy_version));
    fields.insert(
        "credential_digest_prefix".to_owned(),
        json!(record.credential_digest_prefix),
    );
    Value::Object(fields)
}

fn aggregate_json(lane: AccessLane, aggregate: &AccessAggregate) -> Value {
    json!({
        "kind": "aggregate",
        "lane": lane.as_str(),
        "class": aggregate.class.as_str(),
        "occurred_at": unix_micros(aggregate.window_start),
        "route_id": aggregate.route_id.map(|id| id.to_string()),
        "route_template": aggregate.route_template,
        "status": aggregate.status,
        "reason": aggregate.reason.as_str(),
        "count": aggregate.count,
    })
}

/// The microseconds since the Unix epoch; zero before it.
fn unix_micros(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_micros()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
