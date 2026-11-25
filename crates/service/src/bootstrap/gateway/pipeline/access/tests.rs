use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_LENGTH, COOKIE};
use axum::http::request::Parts;
use axum::http::{Request, Response, StatusCode};
use iam_application::{
    AccessLogCounters, AccessLogReceiver, AccessRecordBuilder, AccessRecorder, DecisionTrace,
    access_log_channel,
};
use iam_domain::{
    AccessClass, AccessDecision, AccessLane, Decision, DecisionReason, Rng, SampleRate, SubjectId,
    TokenRejection,
};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;

use super::{Observed, PipelineAccessLog, announced_length};

#[derive(Debug)]
struct ZeroRng;

impl Rng for ZeroRng {
    fn next_u64(&self) -> u64 {
        0
    }
}

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn step() -> (PipelineAccessLog, AccessLogReceiver) {
    let (channel, receiver) = access_log_channel(8, Arc::new(AccessLogCounters::new()));
    let recorder = AccessRecorder::new(
        AccessRecordBuilder::new(Arc::new(ZeroRng), SampleRate::ALL),
        channel,
    );
    let step = PipelineAccessLog::new(
        Arc::new(recorder),
        Arc::new(FixedClock::at(now())),
        Arc::new(SequenceUuidGenerator::starting_at(5)),
    );
    (step, receiver)
}

fn request() -> Parts {
    Request::post("/api/users/424242?apiKey=hunter2")
        .header("host", "API.Example.Test:8443")
        .header("x-request-id", "req-7")
        .header(CONTENT_LENGTH, "42")
        .header(AUTHORIZATION, "Bearer a.b.c")
        .header(COOKIE, "session=cookie-secret")
        .body(())
        .unwrap()
        .into_parts()
        .0
}

fn response(status: StatusCode, length: Option<&str>) -> Response<Body> {
    let mut builder = Response::builder().status(status);
    if let Some(length) = length {
        builder = builder.header(CONTENT_LENGTH, length);
    }
    builder.body(Body::empty()).unwrap()
}

#[test]
fn a_record_carries_the_request_the_verdict_and_the_response_and_none_of_the_secrets() {
    let (step, receiver) = step();
    let started = PipelineAccessLog::begin(&request());
    let mut seen = Observed::default();
    seen.decision(DecisionTrace::default(), vec!["k".to_owned()]);

    step.finish(
        started,
        seen,
        (Decision::Deny, DecisionReason::PermissionMissing),
        &response(StatusCode::FORBIDDEN, Some("17")),
    );

    let item = receiver.try_next().unwrap();
    let record = item.record;
    assert_eq!(item.lane, AccessLane::Audit);
    assert_eq!(item.class, AccessClass::Audit);
    assert_eq!(record.method, "POST");
    assert_eq!(record.host, "api.example.test");
    assert_eq!(record.request_id.as_deref(), Some("req-7"));
    assert_eq!(record.bytes_in, 42);
    assert_eq!(record.bytes_out, 17);
    assert_eq!(record.status, 403);
    assert_eq!(record.decision, AccessDecision::Deny);
    assert_eq!(record.denied, ["k"]);
    assert_eq!(record.occurred_at, now());
    assert_eq!(
        record.credential_digest_prefix.as_ref().map(String::len),
        Some(8)
    );
    let text = format!("{record:?}");
    for secret in ["a.b.c", "cookie-secret", "424242", "hunter2"] {
        assert!(!text.contains(secret), "{secret}");
    }
}

#[test]
fn what_the_pipeline_observed_ends_up_in_the_record() {
    let (step, receiver) = step();
    let started = PipelineAccessLog::begin(&request());
    let mut seen = Observed::default();
    seen.token(&Ok(iam_domain::TokenIdentity::from(
        &iam_domain::AccessToken::new(iam_domain::AccessTokenParts {
            subject: SubjectId::User(
                shared_domain::Uuid::parse("00000000-0000-7000-8000-000000000003").unwrap(),
            ),
            session: None,
            token_id: iam_domain::TokenId::new("jti").unwrap(),
            roles: Vec::new(),
            issued_at: SystemTime::UNIX_EPOCH,
            expires_at: SystemTime::UNIX_EPOCH + Duration::from_secs(60),
        }),
    )));

    step.finish(
        started,
        seen,
        (Decision::Allow, DecisionReason::Allowed),
        &response(StatusCode::OK, None),
    );

    let record = receiver.try_next().unwrap().record;
    assert_eq!(
        record.subject_id.as_deref(),
        Some("00000000-0000-7000-8000-000000000003")
    );
    assert_eq!(record.bytes_out, 0);
    assert_eq!(record.status, 200);
}

#[test]
fn a_refused_token_is_noted_with_its_reason() {
    let mut seen = Observed::default();

    assert_eq!(seen.token_refusal(), None);
    seen.token(&Err(TokenRejection::Expired));

    assert_eq!(seen.token_refusal(), Some(DecisionReason::TokenExpired));
}

#[test]
fn a_length_that_is_not_a_number_is_announced_as_zero() {
    let mut headers = axum::http::HeaderMap::new();
    assert_eq!(announced_length(&headers), 0);
    headers.insert(CONTENT_LENGTH, "many".parse().unwrap());
    assert_eq!(announced_length(&headers), 0);
    headers.insert(CONTENT_LENGTH, "12".parse().unwrap());
    assert_eq!(announced_length(&headers), 12);
}

fn gate() -> Arc<iam_application::AuditGate> {
    Arc::new(iam_application::AuditGate::new(
        Arc::new(FixedClock::at(now())),
        Duration::from_secs(5),
        4,
    ))
}

#[test]
fn a_request_dropped_before_its_record_gives_its_audit_slot_back() {
    let gate = gate();
    let mut seen = Observed::default();
    seen.hold_audit_slot(gate.reserve());
    assert_eq!(gate.reserved(), 1);

    // The client went away while the request was forwarded: the future, and with it the
    // observations, is dropped and `finish` never runs.
    drop(seen);

    assert_eq!(gate.reserved(), 0);
}

#[test]
fn the_record_of_a_finished_request_carries_the_audit_slot_to_the_writer() {
    let (step, receiver) = step();
    let gate = gate();
    let mut seen = Observed::default();
    seen.hold_audit_slot(gate.reserve());

    step.finish(
        PipelineAccessLog::begin(&request()),
        seen,
        (Decision::Deny, DecisionReason::PermissionMissing),
        &response(StatusCode::FORBIDDEN, None),
    );

    assert_eq!(gate.reserved(), 1);
    let item = receiver.try_next().unwrap();
    assert!(item.slot.is_some());
    drop(item);
    assert_eq!(gate.reserved(), 0);
}
