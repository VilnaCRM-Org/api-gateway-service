use std::sync::Arc;
use std::time::SystemTime;

use iam_application::{AccessFacts, RequestFacts, ResponseFacts, VerdictFacts};
use iam_domain::{AccessLane, ClassBudgets, Decision, DecisionReason, SampleRate};
use test_support::access_log_sink::RecordingAccessLogSink;
use test_support::clock::FixedClock;
use test_support::log::LogRecorder;
use test_support::rng::FakeRng;

use super::{AccessLogAdapters, join_writer};
use crate::config::AccessLogSettings;

fn settings(rate: SampleRate, capacity: usize) -> AccessLogSettings {
    AccessLogSettings {
        allow_sample_rate: rate,
        class_budgets: ClassBudgets::new(10, 10),
        channel_capacity: capacity,
    }
}

fn facts(decision: Decision, reason: DecisionReason, status: u16) -> AccessFacts {
    AccessFacts {
        decision_id: shared_domain::Uuid::parse("00000000-0000-7000-8000-000000000001").unwrap(),
        occurred_at: SystemTime::UNIX_EPOCH,
        request: RequestFacts {
            method: "GET".to_owned(),
            host: "api.example.test".to_owned(),
            request_id: None,
            bytes_in: 0,
            credential_digest_prefix: None,
        },
        route: None,
        verdict: VerdictFacts {
            decision,
            reason,
            subject: None,
            policy_version: None,
            trace: iam_application::DecisionTrace::default(),
            denied: Vec::new(),
            project_id: None,
        },
        response: ResponseFacts {
            status,
            bytes_out: 0,
            latency_us: 1,
        },
    }
}

fn started(rate: SampleRate) -> (AccessLogAdapters, Arc<RecordingAccessLogSink>) {
    let sink = Arc::new(RecordingAccessLogSink::new());
    let adapters = AccessLogAdapters::start(
        &settings(rate, 64),
        Arc::new(FakeRng::seeded(5)),
        Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        Arc::<RecordingAccessLogSink>::clone(&sink),
    )
    .unwrap();
    (adapters, sink)
}

#[test]
fn a_recorded_decision_is_written_to_its_lane_by_the_writer_thread() {
    let (adapters, sink) = started(SampleRate::ALL);

    adapters.recorder().record(facts(
        Decision::Deny,
        DecisionReason::PermissionMissing,
        403,
    ));
    adapters
        .recorder()
        .record(facts(Decision::Allow, DecisionReason::Allowed, 200));
    adapters.finish();

    assert_eq!(sink.records(AccessLane::Audit).len(), 1);
    assert_eq!(sink.records(AccessLane::Access).len(), 1);
}

#[test]
fn finishing_twice_is_harmless_and_nothing_is_dropped_on_a_roomy_channel() {
    let (adapters, _sink) = started(SampleRate::NONE);

    adapters.finish();
    adapters.finish();

    assert_eq!(
        adapters
            .counters()
            .dropped_count(AccessLane::Audit, iam_domain::AccessClass::Audit),
        0
    );
}

#[test]
fn the_production_wiring_starts_over_stdout() {
    let adapters = AccessLogAdapters::to_stdout(
        &AccessLogSettings::default(),
        Arc::new(FakeRng::seeded(5)),
        Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
    )
    .unwrap();

    adapters.finish();
}

#[test]
fn a_writer_thread_that_panicked_is_logged_when_it_is_joined() {
    let (recorder, _guard) = LogRecorder::install();
    let handle = std::thread::spawn(|| panic!("the writer failed"));

    join_writer(Some(handle));

    let lines = recorder.lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].message, "the access log writer panicked");
}

#[test]
fn a_writer_thread_that_ended_normally_or_is_gone_logs_nothing() {
    let (recorder, _guard) = LogRecorder::install();

    join_writer(Some(std::thread::spawn(|| {})));
    join_writer(None);

    assert_eq!(recorder.lines().len(), 0);
}

/// Polls `condition` for up to five seconds.
fn eventually(condition: impl Fn() -> bool) -> bool {
    for _ in 0..500 {
        if condition() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    condition()
}

#[test]
fn the_production_wiring_pushes_the_audit_lane_to_loki_and_starts_with_an_open_gate() {
    let audit = crate::config::GatewayConfig::from_args(&{
        let mut args = crate::cli::GatewayArgs::default();
        args.service.app_env = Some("test".to_owned());
        args.service.tokens.public_keys_file =
            Some(test_support::access_token::DEVELOPMENT_PUBLIC_KEYS_FILE.to_owned());
        args.service.kafka.bootstrap_servers = Some("localhost:9092".to_owned());
        args.service.kafka.security_protocol = Some("PLAINTEXT".to_owned());
        args
    })
    .unwrap()
    .audit_lane;

    let adapters = AccessLogAdapters::to_production(
        &AccessLogSettings::default(),
        &audit,
        crate::config::AppEnv::Test,
        Arc::new(FakeRng::seeded(5)),
        Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
    )
    .unwrap();

    assert!(adapters.audit_gate().admits());
    adapters.finish();
}

#[test]
fn an_audit_record_that_the_sink_does_not_acknowledge_closes_the_gate_until_it_does() {
    let sink = Arc::new(RecordingAccessLogSink::withholding());
    let clock = Arc::new(test_support::clock::ManualClock::at(SystemTime::UNIX_EPOCH));
    let gate = Arc::new(iam_application::AuditGate::new(
        Arc::<test_support::clock::ManualClock>::clone(&clock),
        std::time::Duration::from_secs(5),
        64,
    ));
    let adapters = AccessLogAdapters::start_gated(
        &settings(SampleRate::NONE, 64),
        Arc::clone(&gate),
        Arc::new(FakeRng::seeded(5)),
        Arc::<test_support::clock::ManualClock>::clone(&clock),
        Arc::<RecordingAccessLogSink>::clone(&sink),
    )
    .unwrap();
    adapters.recorder().record(facts(
        Decision::Deny,
        DecisionReason::PermissionMissing,
        403,
    ));
    assert!(eventually(|| gate.pending() == 1));

    clock.advance(std::time::Duration::from_secs(6));
    assert!(!gate.admits());
    sink.acknowledge(1);

    assert!(eventually(|| gate.admits()));
    assert_eq!(gate.pending(), 0);
    adapters.finish();
}

#[test]
fn the_pipeline_step_carries_the_audit_gate_of_the_adapters() {
    let (adapters, _sink) = started(SampleRate::NONE);
    let clock: Arc<dyn shared_domain::Clock> = Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH));

    let step = adapters.pipeline_step(&clock);

    assert!(step.audit_gate().is_some());
    adapters.finish();
}
