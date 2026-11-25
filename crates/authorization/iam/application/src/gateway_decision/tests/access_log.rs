//! The access records of the checks of the decision API.

use std::sync::Arc;

use iam_domain::{DecisionReason, Rng, SampleRate};
use test_support::clock::FixedClock;
use test_support::request_digester::FakeRequestDigester;

use super::{Scenario, batch, permissions, query, scenario, single};
use crate::access_log::{
    AccessLogCounters, AccessLogReceiver, AccessRecordBuilder, AccessRecorder,
    BATCH_VALIDATION_TEMPLATE, DecisionAccessLog, VALIDATION_TEMPLATE, access_log_channel,
};
use crate::query::validate_access_batch::BatchCheck;

#[derive(Debug)]
struct ZeroRng;

impl Rng for ZeroRng {
    fn next_u64(&self) -> u64 {
        0
    }
}

fn recorded() -> (Scenario, AccessLogReceiver) {
    let (channel, receiver) = access_log_channel(32, Arc::new(AccessLogCounters::new()));
    let recorder = AccessRecorder::new(
        AccessRecordBuilder::new(Arc::new(ZeroRng), SampleRate::ALL),
        channel,
    );
    let log = Arc::new(DecisionAccessLog::new(
        Arc::new(recorder),
        Arc::new(FixedClock::at(std::time::SystemTime::UNIX_EPOCH)),
        Arc::new(FakeRequestDigester),
    ));
    let Scenario {
        single,
        batch,
        tokens,
        clock,
    } = scenario();
    let single = single.with_access_log(Arc::clone(&log));
    let batch = batch.with_access_log(log);
    (
        Scenario {
            single,
            batch,
            tokens,
            clock,
        },
        receiver,
    )
}

#[tokio::test]
async fn a_single_check_leaves_one_record_with_the_decision_id_of_its_response() {
    let (scenario, receiver) = recorded();

    let outcome = single(&scenario, query("expired", permissions(), None)).await;

    let item = receiver.try_next().unwrap();
    assert!(receiver.try_next().is_none());
    assert_eq!(item.record.decision_id, outcome.decision_id().as_uuid());
    assert_eq!(item.record.reason, DecisionReason::TokenExpired);
    assert_eq!(
        item.record.route_template.as_deref(),
        Some(VALIDATION_TEMPLATE)
    );
    assert_eq!(item.lane, iam_domain::AccessLane::Audit);
    assert!(item.record.credential_digest_prefix.is_some());
    assert!(!format!("{:?}", item.record).contains("expired\""));
}

#[tokio::test]
async fn a_check_that_cannot_be_decided_is_recorded_as_unavailable() {
    let (scenario, receiver) = recorded();

    single(&scenario, query("expired", permissions(), Some(99))).await;

    let item = receiver.try_next().unwrap();
    assert_eq!(item.record.reason, DecisionReason::Unavailable);
    assert_eq!(item.class, iam_domain::AccessClass::Error);
}

#[tokio::test]
async fn every_item_of_a_batch_leaves_a_record_and_a_malformed_one_has_no_digest() {
    let (scenario, receiver) = recorded();
    let checks = vec![
        BatchCheck::Valid(query("expired", permissions(), None)),
        BatchCheck::Malformed,
    ];

    let outcomes = batch(&scenario, checks).await;

    let first = receiver.try_next().unwrap();
    let second = receiver.try_next().unwrap();
    assert!(receiver.try_next().is_none());
    assert_eq!(
        first.record.decision_id,
        outcomes[0].decision_id().as_uuid()
    );
    assert_eq!(
        second.record.decision_id,
        outcomes[1].decision_id().as_uuid()
    );
    assert_eq!(
        first.record.route_template.as_deref(),
        Some(BATCH_VALIDATION_TEMPLATE)
    );
    assert_eq!(second.record.reason, DecisionReason::MalformedOperation);
    assert!(second.record.credential_digest_prefix.is_none());
}
