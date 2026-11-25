use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessDecision, AccessEntry, AccessLane, AccessLogSink as _, AccessRecord, DecisionReason,
};
use serde_json::Value;
use shared_domain::Uuid;

use super::{BATCH_BYTES, LokiPushAccessLogSink, LokiSinkSettings, LokiTransport};

#[derive(Debug, Default)]
struct FakeLoki {
    accepting: AtomicBool,
    bodies: Mutex<Vec<String>>,
    attempts: Mutex<u32>,
}

impl FakeLoki {
    fn accepting() -> Arc<Self> {
        let loki = Self::default();
        loki.accepting.store(true, Ordering::Release);
        Arc::new(loki)
    }

    fn withholding() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn accept(&self) {
        self.accepting.store(true, Ordering::Release);
    }

    fn bodies(&self) -> Vec<String> {
        self.bodies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn attempts(&self) -> u32 {
        *self.attempts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The decision ids of every acknowledged push, in order.
    fn pushed_ids(&self) -> Vec<String> {
        self.bodies()
            .iter()
            .flat_map(|body| {
                let body: Value = serde_json::from_str(body).unwrap();
                body["streams"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .flat_map(|stream| stream["values"].as_array().unwrap().clone())
                    .map(|value| value[2]["decision_id"].as_str().unwrap().to_owned())
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

impl LokiTransport for FakeLoki {
    fn push(&self, body: &str) -> bool {
        let mut attempts = self.attempts.lock().unwrap_or_else(PoisonError::into_inner);
        *attempts = attempts.saturating_add(1);
        drop(attempts);
        let accepted = self.accepting.load(Ordering::Acquire);
        if accepted {
            self.bodies
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(body.to_owned());
        }
        accepted
    }
}

/// A transport whose push panics, which ends the worker thread.
#[derive(Debug, Default)]
struct PanickingLoki {
    attempts: Mutex<u32>,
}

impl LokiTransport for PanickingLoki {
    fn push(&self, _body: &str) -> bool {
        let mut attempts = self.attempts.lock().unwrap_or_else(PoisonError::into_inner);
        *attempts = attempts.saturating_add(1);
        drop(attempts);
        panic!("the transport broke");
    }
}

fn settings(interval: Duration) -> LokiSinkSettings {
    LokiSinkSettings {
        app: "gateway".to_owned(),
        env: "test".to_owned(),
        flush_interval: interval,
    }
}

fn entry(counter: u32, padding: usize) -> AccessEntry {
    AccessEntry::Record(Box::new(AccessRecord {
        decision_id: Uuid::parse(&format!("00000000-0000-7000-8000-{counter:012x}")).unwrap(),
        occurred_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_hours(500_000))
            .unwrap(),
        method: "DELETE".to_owned(),
        host: "api.example.test".to_owned(),
        route_id: None,
        route_template: None,
        status: 403,
        upstream: Some("orders".to_owned()),
        latency_us: 1,
        bytes_in: 0,
        bytes_out: 0,
        request_id: Some("r".repeat(padding)),
        subject_id: None,
        subject_kind: None,
        decision: AccessDecision::Deny,
        reason: DecisionReason::PermissionMissing,
        permission_key: None,
        denied: Vec::new(),
        project_id: None,
        policy_version: None,
        credential_digest_prefix: None,
    }))
}

/// Polls `condition` for up to five seconds.
fn eventually(condition: impl Fn() -> bool) -> bool {
    for _ in 0..500 {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    condition()
}

fn sink(loki: &Arc<FakeLoki>, interval: Duration) -> LokiPushAccessLogSink {
    LokiPushAccessLogSink::start(settings(interval), Arc::<FakeLoki>::clone(loki)).unwrap()
}

#[test]
fn entries_are_pushed_after_the_flush_interval_and_counted_once_acknowledged() {
    let loki = FakeLoki::accepting();
    let sink = sink(&loki, Duration::from_millis(20));

    sink.write(AccessLane::Audit, &entry(1, 0));
    sink.write(AccessLane::Audit, &entry(2, 0));

    assert!(eventually(|| sink.acknowledged_audit() == Some(2)));
    assert_eq!(loki.pushed_ids().len(), 2);
}

#[test]
fn nothing_is_acknowledged_while_loki_refuses_and_the_entries_are_pushed_again_afterwards() {
    let loki = FakeLoki::withholding();
    let sink = sink(&loki, Duration::from_millis(20));
    sink.write(AccessLane::Audit, &entry(1, 0));

    assert!(eventually(|| loki.attempts() >= 2));
    assert_eq!(sink.acknowledged_audit(), Some(0));
    loki.accept();

    assert!(eventually(|| sink.acknowledged_audit() == Some(1)));
    assert_eq!(loki.pushed_ids().len(), 1);
}

#[test]
fn an_acknowledged_entry_is_never_pushed_twice() {
    let loki = FakeLoki::accepting();
    let sink = sink(&loki, Duration::from_millis(10));
    sink.write(AccessLane::Audit, &entry(1, 0));
    assert!(eventually(|| sink.acknowledged_audit() == Some(1)));

    sink.write(AccessLane::Audit, &entry(2, 0));
    assert!(eventually(|| sink.acknowledged_audit() == Some(2)));
    sink.flush();

    let mut ids = loki.pushed_ids();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 2);
    assert_eq!(loki.pushed_ids().len(), 2);
}

#[test]
fn a_mebibyte_of_entries_is_pushed_without_waiting_for_the_interval() {
    let loki = FakeLoki::accepting();
    let sink = sink(&loki, Duration::from_secs(3_600));

    for counter in 0..4 {
        sink.write(AccessLane::Audit, &entry(counter, BATCH_BYTES / 3));
    }

    assert!(eventually(|| sink
        .acknowledged_audit()
        .is_some_and(|count| count >= 3)));
    assert!(
        loki.bodies()
            .iter()
            .all(|body| body.len() <= BATCH_BYTES.saturating_mul(2))
    );
}

#[test]
fn flushing_pushes_what_is_queued_and_a_second_flush_does_nothing() {
    let loki = FakeLoki::accepting();
    let sink = sink(&loki, Duration::from_secs(3_600));
    sink.write(AccessLane::Audit, &entry(1, 0));

    sink.flush();
    sink.flush();

    assert_eq!(sink.acknowledged_audit(), Some(1));
    assert_eq!(loki.pushed_ids().len(), 1);
}

#[test]
fn flushing_against_a_refusing_loki_acknowledges_nothing() {
    let loki = FakeLoki::withholding();
    let sink = sink(&loki, Duration::from_secs(3_600));
    sink.write(AccessLane::Audit, &entry(1, 0));

    sink.flush();

    assert_eq!(sink.acknowledged_audit(), Some(0));
    assert!(loki.attempts() >= 1);
}

#[test]
fn dropping_the_sink_stops_the_worker() {
    let loki = FakeLoki::accepting();
    let sink = sink(&loki, Duration::from_secs(3_600));
    sink.write(AccessLane::Audit, &entry(1, 0));

    drop(sink);

    assert_eq!(loki.pushed_ids().len(), 1);
}

#[test]
fn a_worker_that_panicked_is_logged_when_the_sink_stops_and_the_stop_returns() {
    let transport = Arc::new(PanickingLoki::default());
    let sink = LokiPushAccessLogSink::start(
        settings(Duration::from_secs(3_600)),
        Arc::<PanickingLoki>::clone(&transport),
    )
    .unwrap();
    sink.write(AccessLane::Audit, &entry(1, 0));

    drop(sink);

    assert_eq!(
        *transport
            .attempts
            .lock()
            .unwrap_or_else(PoisonError::into_inner),
        1
    );
}
