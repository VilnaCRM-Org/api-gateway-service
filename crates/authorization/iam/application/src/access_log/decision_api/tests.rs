use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessCheck, AccessTarget, Credential, DecisionId, DecisionOutcome, DecisionReason,
    DecisionVerdict, HttpMethod, ProjectId, RequestDigest, RequestDigester, RestTarget, Rng,
    SampleRate, ScopeSet, ServiceName, SubjectRef,
};
use shared_domain::Uuid;
use test_support::clock::FixedClock;

use super::{
    BATCH_VALIDATION_TEMPLATE, DECISION_API_HOST, DecisionAccessLog, DecisionCall,
    VALIDATION_TEMPLATE,
};
use crate::access_log::builder::AccessRecordBuilder;
use crate::access_log::channel::{AccessLogReceiver, access_log_channel};
use crate::access_log::counters::AccessLogCounters;
use crate::access_log::facts::DecisionTrace;
use crate::access_log::recorder::AccessRecorder;

#[derive(Debug)]
struct ZeroRng;

impl Rng for ZeroRng {
    fn next_u64(&self) -> u64 {
        0
    }
}

/// A digester whose digest starts with the bytes 0xde 0xad 0xbe 0xef.
#[derive(Debug)]
struct FixedDigester;

impl RequestDigester for FixedDigester {
    fn digest(&self, _canonical: &str) -> RequestDigest {
        let mut bytes = [0_u8; RequestDigest::LENGTH];
        bytes[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        RequestDigest::from_bytes(bytes)
    }
}

fn log() -> (DecisionAccessLog, AccessLogReceiver) {
    let (channel, receiver) = access_log_channel(8, Arc::new(AccessLogCounters::new()));
    let recorder = AccessRecorder::new(
        AccessRecordBuilder::new(Arc::new(ZeroRng), SampleRate::ALL),
        channel,
    );
    let log = DecisionAccessLog::new(
        Arc::new(recorder),
        Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        Arc::new(FixedDigester),
    );
    (log, receiver)
}

fn id(counter: u32) -> Uuid {
    Uuid::parse(&format!("00000000-0000-7000-8000-{counter:012x}")).unwrap()
}

fn check() -> AccessCheck {
    AccessCheck::new(
        ServiceName::new("orders").unwrap(),
        AccessTarget::Rest(RestTarget::new(HttpMethod::Get, "/api/orders/7".to_owned())),
        None,
        None,
    )
}

#[test]
fn a_check_is_recorded_with_the_decision_id_of_its_response() {
    let (log, receiver) = log();
    let outcome = DecisionOutcome::new(
        DecisionVerdict::deny(DecisionReason::PermissionMissing, vec!["k".to_owned()]),
        DecisionId::from_uuid(id(9)),
        Some(SubjectRef::user(id(3))),
        Some(iam_domain::PolicyVersion::new(12).unwrap()),
    );
    let credential = Credential::new("secret-token".to_owned());

    log.record(&DecisionCall {
        template: VALIDATION_TEMPLATE,
        credential: &credential,
        check: Some(&check()),
        outcome: &outcome,
        trace: &DecisionTrace::default(),
        latency: Duration::from_micros(250),
    });

    let item = receiver.try_next().unwrap();
    let record = item.record;
    assert_eq!(record.decision_id, id(9));
    assert_eq!(record.method, "POST");
    assert_eq!(record.host, DECISION_API_HOST);
    assert_eq!(record.route_template.as_deref(), Some(VALIDATION_TEMPLATE));
    assert!(record.route_id.is_none());
    assert_eq!(record.status, 200);
    assert_eq!(record.latency_us, 250);
    assert_eq!(record.reason, DecisionReason::PermissionMissing);
    assert_eq!(record.denied, ["k"]);
    assert_eq!(record.subject_id, Some(id(3).to_string()));
    assert_eq!(record.policy_version, Some(12));
    assert_eq!(record.credential_digest_prefix.as_deref(), Some("deadbeef"));
    assert!(!format!("{record:?}").contains("secret-token"));
}

#[test]
fn a_batch_item_with_a_blank_credential_has_no_digest_prefix_and_an_allow_is_sampled() {
    let (log, receiver) = log();
    let outcome = DecisionOutcome::new(
        DecisionVerdict::allow(ScopeSet::All),
        DecisionId::from_uuid(id(1)),
        None,
        None,
    );
    let credential = Credential::new(String::new());

    log.record(&DecisionCall {
        template: BATCH_VALIDATION_TEMPLATE,
        credential: &credential,
        check: None,
        outcome: &outcome,
        trace: &DecisionTrace::default(),
        latency: Duration::ZERO,
    });

    let record = receiver.try_next().unwrap().record;
    assert_eq!(
        record.route_template.as_deref(),
        Some(BATCH_VALIDATION_TEMPLATE)
    );
    assert!(record.credential_digest_prefix.is_none());
    assert!(record.project_id.is_none());
}

#[test]
fn the_project_of_a_check_is_recorded() {
    let (log, receiver) = log();
    let outcome = DecisionOutcome::new(
        DecisionVerdict::allow(ScopeSet::All),
        DecisionId::from_uuid(id(2)),
        None,
        None,
    );
    let credential = Credential::new("token".to_owned());
    let project = ProjectId::parse(&id(77).to_string()).unwrap();
    let check = AccessCheck::new(
        ServiceName::new("orders").unwrap(),
        AccessTarget::Rest(RestTarget::new(HttpMethod::Get, "/api/orders/7".to_owned())),
        Some(project),
        None,
    );

    log.record(&DecisionCall {
        template: VALIDATION_TEMPLATE,
        credential: &credential,
        check: Some(&check),
        outcome: &outcome,
        trace: &DecisionTrace::default(),
        latency: Duration::ZERO,
    });

    let record = receiver.try_next().unwrap().record;
    assert_eq!(record.project_id, Some(id(77)));
}
