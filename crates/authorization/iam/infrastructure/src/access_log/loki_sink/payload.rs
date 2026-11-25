//! The body of a Loki push request for audit-lane entries (Story 14.2, FR-50).

use std::collections::BTreeMap;
use std::time::SystemTime;

use iam_domain::{AccessAggregate, AccessEntry, AccessLane, AccessRecord};
use serde_json::{Map, Value, json};

use crate::access_log::stdout_sink::render_entry;

/// The value of the `upstream` label of an entry that names none.
const NO_UPSTREAM: &str = "none";

/// The value of the `decision` label of an aggregate, which stands for many decisions.
const AGGREGATE_DECISION: &str = "aggregate";

/// The labels that make a stream: the fixed `app` and `env` are added when the body is built.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Stream {
    pub(super) lane: &'static str,
    pub(super) decision: &'static str,
    pub(super) upstream: String,
}

/// One entry waiting to be pushed: its stream, its timestamp, its line and its structured
/// metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PendingLine {
    pub(super) stream: Stream,
    pub(super) timestamp_ns: u64,
    pub(super) line: String,
    pub(super) metadata: Vec<(&'static str, String)>,
}

impl PendingLine {
    /// The bytes the entry adds to a batch: its line and the metadata it carries.
    pub(super) fn size(&self) -> usize {
        self.metadata
            .iter()
            .map(|(name, value)| name.len().saturating_add(value.len()))
            .fold(self.line.len(), usize::saturating_add)
    }
}

/// The line to push for `entry` of `lane`.
pub(super) fn pending_of(lane: AccessLane, entry: &AccessEntry) -> PendingLine {
    let rendered = render_entry(lane, entry);
    match entry {
        AccessEntry::Record(record) => PendingLine {
            stream: Stream {
                lane: lane.as_str(),
                decision: record.decision.as_str(),
                upstream: record
                    .upstream
                    .clone()
                    .unwrap_or_else(|| NO_UPSTREAM.to_owned()),
            },
            timestamp_ns: nanos(record.occurred_at),
            line: rendered,
            metadata: record_metadata(record),
        },
        AccessEntry::Aggregate(aggregate) => PendingLine {
            stream: Stream {
                lane: lane.as_str(),
                decision: AGGREGATE_DECISION,
                upstream: NO_UPSTREAM.to_owned(),
            },
            timestamp_ns: nanos(aggregate.window_start),
            line: rendered,
            metadata: aggregate_metadata(aggregate),
        },
    }
}

/// The structured metadata of a record; a field the record does not have is left out.
fn record_metadata(record: &AccessRecord) -> Vec<(&'static str, String)> {
    let mut metadata = Vec::new();
    push_some(&mut metadata, "subject_id", record.subject_id.clone());
    metadata.push(("decision_id", record.decision_id.to_string()));
    push_some(&mut metadata, "request_id", record.request_id.clone());
    push_some(
        &mut metadata,
        "route_id",
        record.route_id.map(|id| id.to_string()),
    );
    metadata.push(("status", record.status.to_string()));
    metadata.push(("reason", record.reason.as_str().to_owned()));
    push_some(
        &mut metadata,
        "policy_version",
        record.policy_version.map(|version| version.to_string()),
    );
    push_some(
        &mut metadata,
        "subject_kind",
        record.subject_kind.map(|kind| kind.as_str().to_owned()),
    );
    metadata
}

/// The structured metadata of an aggregate.
fn aggregate_metadata(aggregate: &AccessAggregate) -> Vec<(&'static str, String)> {
    let mut metadata = Vec::new();
    push_some(
        &mut metadata,
        "route_id",
        aggregate.route_id.map(|id| id.to_string()),
    );
    metadata.push(("status", aggregate.status.to_string()));
    metadata.push(("reason", aggregate.reason.as_str().to_owned()));
    metadata
}

fn push_some(
    metadata: &mut Vec<(&'static str, String)>,
    name: &'static str,
    value: Option<String>,
) {
    if let Some(value) = value {
        metadata.push((name, value));
    }
}

/// The nanoseconds since the Unix epoch; zero before it.
fn nanos(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok())
        .unwrap_or(0)
}

/// The JSON body of `POST /loki/api/v1/push` for `lines`: one stream per label set, with the
/// structured metadata of each entry as the third element of its value.
pub(super) fn push_body(app: &str, env: &str, lines: &[PendingLine]) -> String {
    let mut streams: BTreeMap<&Stream, Vec<&PendingLine>> = BTreeMap::new();
    for line in lines {
        streams.entry(&line.stream).or_default().push(line);
    }
    let streams: Vec<Value> = streams
        .into_iter()
        .map(|(stream, mut lines)| {
            lines.sort_by_key(|line| line.timestamp_ns);
            json!({
                "stream": {
                    "app": app,
                    "env": env,
                    "lane": stream.lane,
                    "decision": stream.decision,
                    "upstream": stream.upstream,
                },
                "values": lines.into_iter().map(value_of).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({ "streams": streams }).to_string()
}

fn value_of(line: &PendingLine) -> Value {
    let metadata: Map<String, Value> = line
        .metadata
        .iter()
        .map(|(name, value)| ((*name).to_owned(), Value::String(value.clone())))
        .collect();
    json!([line.timestamp_ns.to_string(), line.line, metadata])
}

#[cfg(test)]
mod tests;
