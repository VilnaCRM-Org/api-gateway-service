use std::sync::Arc;

use iam_domain::{
    CatalogueEntryState, FramedRecord, InvalidStateRecord, PolicyDigestValue, PolicyState,
    PolicyVersion, StateKey, StateRecordCodec, SubjectRef, SubjectState, TAIL_READ_LIMIT,
};
use shared_domain::Uuid;
use test_support::anti_entropy::{HashDigest, TextHeadCodec};
use test_support::policy_bootstrap_log::{
    FakePolicyBootstrapLog, by_relay, framed_head, framed_row,
};

use super::{
    BootstrapAction, BootstrapFailure, BootstrapInput, BootstrapMachine, BootstrapOutcome,
    BootstrapPorts, BootstrapSnapshot, run_bootstrap,
};

const ROLE: &str = "role/0192f6a0-0000-7000-8000-000000000001";
const OTHER: &str = "role/0192f6a0-0000-7000-8000-000000000002";
const THIRD: &str = "role/0192f6a0-0000-7000-8000-000000000003";

fn ports() -> BootstrapPorts {
    BootstrapPorts {
        codec: Arc::new(TextHeadCodec),
        digest: Arc::new(HashDigest),
    }
}

fn machine() -> BootstrapMachine {
    BootstrapMachine::new(ports())
}

fn digest_of(entities: &[(&str, &str)]) -> PolicyDigestValue {
    entities
        .iter()
        .map(|(key, canonical)| HashDigest::of(key, canonical))
        .fold(PolicyDigestValue::ZERO, PolicyDigestValue::combined)
}

fn version(number: i64) -> PolicyVersion {
    PolicyVersion::new(number).unwrap()
}

fn row(offset: i64, key: &str, payload: &str, number: i64, framing: (u32, u32)) -> FramedRecord {
    let (seq, count) = framing;
    framed_row(
        offset,
        key,
        Some(payload),
        number,
        (seq, count, PolicyDigestValue::ZERO),
    )
}

/// Version 1: two roles and the head.
fn first_version() -> Vec<FramedRecord> {
    let digest = digest_of(&[(ROLE, "a"), (OTHER, "b")]);
    vec![
        row(0, ROLE, "a", 1, (1, 3)),
        row(1, OTHER, "b", 1, (2, 3)),
        framed_head(2, 1, 3, digest),
    ]
}

async fn run(log: &FakePolicyBootstrapLog) -> BootstrapOutcome {
    run_bootstrap(machine(), log).await
}

fn started(outcome: BootstrapOutcome) -> BootstrapSnapshot {
    match outcome {
        BootstrapOutcome::Started(snapshot) => snapshot,
        BootstrapOutcome::NotStarted(failure) => panic!("not started: {failure}"),
    }
}

fn not_started(outcome: BootstrapOutcome) -> BootstrapFailure {
    match outcome {
        BootstrapOutcome::NotStarted(failure) => failure,
        BootstrapOutcome::Started(snapshot) => panic!("started at {:?}", snapshot.version),
    }
}

#[tokio::test]
async fn an_empty_topic_publishes_version_zero() {
    let log = FakePolicyBootstrapLog::with(Vec::new());

    let snapshot = started(run(&log).await);

    assert_eq!(snapshot.version, PolicyVersion::ZERO);
    assert_eq!(snapshot.entries, Vec::new());
    assert_eq!(snapshot.digest, PolicyDigestValue::ZERO);
    assert_eq!(log.closes(), 1);
}

#[tokio::test]
async fn a_complete_topic_publishes_the_version_of_its_head() {
    let log = FakePolicyBootstrapLog::with(first_version());

    let snapshot = started(run(&log).await);

    assert_eq!(snapshot.version, version(1));
    assert_eq!(snapshot.digest, digest_of(&[(ROLE, "a"), (OTHER, "b")]));
    assert_eq!(snapshot.entries.len(), 2);
    assert_eq!(snapshot.incomplete, None);
    assert_eq!((log.captures(), log.reads()), (1, 1));
}

#[tokio::test]
async fn the_highest_version_of_a_key_wins_and_a_tombstone_deletes_it() {
    let mut records = first_version();
    let digest = digest_of(&[(ROLE, "a2")]);
    records.push(row(3, ROLE, "a2", 2, (1, 3)));
    records.push(framed_row(
        4,
        OTHER,
        None,
        2,
        (2, 3, PolicyDigestValue::ZERO),
    ));
    records.push(framed_head(5, 2, 3, digest));
    let log = FakePolicyBootstrapLog::with(records);

    let snapshot = started(run(&log).await);

    assert_eq!(snapshot.version, version(2));
    assert_eq!(snapshot.entries.len(), 1);
    assert_eq!(snapshot.entries.first().unwrap().payload, "a2");
    assert_eq!(snapshot.entries.first().unwrap().version, version(2));
}

#[tokio::test]
async fn a_version_that_the_relay_left_half_written_is_reported_and_the_previous_one_published() {
    let mut records = first_version();
    records.push(row(3, THIRD, "c", 2, (1, 3)));
    let log = FakePolicyBootstrapLog::with(records);

    let snapshot = started(run(&log).await);

    assert_eq!(snapshot.version, version(1));
    assert_eq!(snapshot.incomplete, Some(version(2)));
    assert_eq!(snapshot.entries.len(), 2);
    assert_eq!(
        log.captures(),
        2,
        "the straddling version is read for once more"
    );
}

#[tokio::test]
async fn a_trailing_row_of_a_known_key_leaves_the_state_of_the_complete_version() {
    let mut records = first_version();
    records.push(row(3, ROLE, "a-later", 2, (1, 3)));
    let log = FakePolicyBootstrapLog::with(records);

    let snapshot = started(run(&log).await);

    assert_eq!(snapshot.version, version(1));
    assert_eq!(snapshot.incomplete, Some(version(2)));
    assert_eq!(snapshot.digest, digest_of(&[(ROLE, "a"), (OTHER, "b")]));
}

#[tokio::test]
async fn the_version_that_straddles_the_captured_offset_is_finished() {
    let mut records = first_version();
    let digest = digest_of(&[(ROLE, "a"), (OTHER, "b"), (THIRD, "c")]);
    records.push(row(3, THIRD, "c", 2, (1, 2)));
    records.push(framed_head(4, 2, 2, digest));
    let log = FakePolicyBootstrapLog::scripted(records, &[4, 5]);

    let snapshot = started(run(&log).await);

    assert_eq!(snapshot.version, version(2));
    assert_eq!(snapshot.incomplete, None);
    assert_eq!(snapshot.entries.len(), 3);
    assert_eq!((log.captures(), log.reads()), (2, 2));
}

#[tokio::test]
async fn a_record_above_the_highest_complete_head_leaves_the_pod_not_started_after_one_retry() {
    let mut records = first_version();
    records.push(row(3, THIRD, "c", 4, (1, 3)));
    let log = FakePolicyBootstrapLog::with(records);

    let failure = not_started(run(&log).await);

    assert_eq!(failure, BootstrapFailure::VersionAboveHead { version: 4 });
    assert_eq!(log.captures(), 2, "one attempt and exactly one retry");
    assert_eq!(log.closes(), 1);
}

#[tokio::test]
async fn an_inconsistent_trailing_version_fails_closed() {
    let mut records = first_version();
    records.push(row(3, THIRD, "c", 2, (1, 3)));
    records.push(row(4, ROLE, "d", 2, (2, 5)));
    let log = FakePolicyBootstrapLog::with(records);

    let failure = not_started(run(&log).await);

    assert_eq!(failure, BootstrapFailure::VersionAboveHead { version: 2 });
}

#[tokio::test]
async fn a_rebuilt_digest_that_differs_from_the_head_is_retried_once_and_then_not_started() {
    let records = vec![
        row(0, ROLE, "a", 1, (1, 2)),
        framed_head(1, 1, 2, digest_of(&[(ROLE, "x")])),
    ];
    let log = FakePolicyBootstrapLog::with(records);

    let failure = not_started(run(&log).await);

    assert!(matches!(
        failure,
        BootstrapFailure::DigestMismatch { version: 1, .. }
    ));
    assert_eq!((log.captures(), log.reads()), (2, 2));
}

#[test]
fn the_step_function_requests_exactly_one_retry_for_a_digest_mismatch() {
    let records = vec![
        row(0, ROLE, "a", 1, (1, 2)),
        framed_head(1, 1, 2, digest_of(&[(ROLE, "x")])),
    ];
    let (state, actions) = machine().step(BootstrapInput::Start);
    assert_eq!(actions, vec![BootstrapAction::CaptureStableEnd]);
    let (state, actions) = state.step(BootstrapInput::StableEnd(2));
    assert_eq!(actions, vec![BootstrapAction::Read { from: 0, up_to: 2 }]);

    let (state, actions) = state.step(BootstrapInput::Records(records.clone()));

    assert!(matches!(
        actions.as_slice(),
        [
            BootstrapAction::Retry(BootstrapFailure::DigestMismatch { .. }),
            BootstrapAction::CaptureStableEnd
        ]
    ));
    let (state, actions) = state.step(BootstrapInput::StableEnd(2));
    assert_eq!(actions, vec![BootstrapAction::Read { from: 0, up_to: 2 }]);
    let (_state, actions) = state.step(BootstrapInput::Records(records));
    assert!(matches!(
        actions.as_slice(),
        [BootstrapAction::NotStarted(
            BootstrapFailure::DigestMismatch { .. }
        )]
    ));
}

#[test]
fn an_input_that_does_not_fit_the_phase_asks_for_nothing() {
    let (state, actions) = machine().step(BootstrapInput::StableEnd(3));
    assert_eq!(actions, Vec::new());
    let (state, actions) = state.step(BootstrapInput::Records(Vec::new()));
    assert_eq!(actions, Vec::new());
    let (state, _actions) = state.step(BootstrapInput::Start);
    let (_state, actions) = state.step(BootstrapInput::Start);
    assert_eq!(actions, Vec::new());
}

#[tokio::test]
async fn a_topic_that_cannot_be_read_is_retried_once_and_then_not_started() {
    let log = FakePolicyBootstrapLog::with(first_version()).unavailable();

    let failure = not_started(run(&log).await);

    assert!(matches!(failure, BootstrapFailure::ReadFailed(_)));
    assert_eq!(log.captures(), 2);
}

#[tokio::test]
async fn a_head_that_cannot_be_read_fails_closed() {
    let mut head = framed_head(1, 1, 2, PolicyDigestValue::ZERO);
    head.record.payload = Some("not a head".to_owned());
    let log = FakePolicyBootstrapLog::with(vec![row(0, ROLE, "a", 1, (1, 2)), head]);

    let failure = not_started(run(&log).await);

    assert!(matches!(failure, BootstrapFailure::UnreadableHead(_)));
}

#[tokio::test]
async fn a_head_without_a_value_fails_closed() {
    let mut head = framed_head(1, 1, 2, PolicyDigestValue::ZERO);
    head.record.payload = None;
    let log = FakePolicyBootstrapLog::with(vec![head]);

    let failure = not_started(run(&log).await);

    assert!(matches!(failure, BootstrapFailure::UnreadableHead(_)));
}

#[tokio::test]
async fn the_late_append_of_a_zombie_relay_is_ignored() {
    let mut records = first_version();
    records.push(by_relay(row(3, OTHER, "b", 1, (2, 3)), 2));
    records.push(by_relay(row(4, THIRD, "ignored", 1, (3, 3)), 0));
    let log = FakePolicyBootstrapLog::with(records);

    let snapshot = started(run(&log).await);

    assert_eq!(snapshot.version, version(1));
    assert_eq!(snapshot.entries.len(), 2);
}

#[tokio::test]
async fn a_topic_longer_than_one_read_is_read_in_several_ranges() {
    let total = TAIL_READ_LIMIT + 20;
    let keys: Vec<String> = (1..=total)
        .map(|number| format!("role/0192f6a0-0000-7000-8000-{number:012x}"))
        .collect();
    let count = u32::try_from(total + 1).unwrap();
    let mut records: Vec<FramedRecord> = keys
        .iter()
        .zip(0_i64..)
        .zip(1_u32..)
        .map(|((key, offset), seq)| row(offset, key, "p", 1, (seq, count)))
        .collect();
    let entities: Vec<(&str, &str)> = keys.iter().map(|key| (key.as_str(), "p")).collect();
    records.push(framed_head(
        i64::try_from(total).unwrap(),
        1,
        count,
        digest_of(&entities),
    ));
    let log = FakePolicyBootstrapLog::with(records);

    let snapshot = started(run(&log).await);

    assert_eq!(snapshot.entries.len(), total);
    assert_eq!(log.reads(), 2);
}

#[tokio::test]
async fn a_key_written_in_three_versions_keeps_its_newest_state() {
    let mut records = first_version();
    records.push(row(3, ROLE, "a2", 2, (1, 2)));
    records.push(framed_head(
        4,
        2,
        2,
        digest_of(&[(ROLE, "a2"), (OTHER, "b")]),
    ));
    records.push(row(5, ROLE, "a3", 3, (1, 2)));
    records.push(framed_head(
        6,
        3,
        2,
        digest_of(&[(ROLE, "a3"), (OTHER, "b")]),
    ));
    let log = FakePolicyBootstrapLog::with(records);

    let snapshot = started(run(&log).await);

    assert_eq!(snapshot.version, version(3));
    assert_eq!(snapshot.entries.len(), 2);
    assert!(
        snapshot
            .entries
            .iter()
            .any(|entry| entry.payload == "a3" && entry.version == version(3)),
        "{:?}",
        snapshot.entries
    );
}

/// A codec whose every record is the state of a subject, so that the head decodes to the state
/// of another entity.
#[derive(Debug)]
struct SubjectCodec(SubjectRef);

impl StateRecordCodec for SubjectCodec {
    fn encode(&self, _state: &PolicyState) -> Result<String, InvalidStateRecord> {
        Err(InvalidStateRecord::Encoding)
    }

    fn decode(&self, _key: &StateKey, _payload: &str) -> Result<PolicyState, InvalidStateRecord> {
        Ok(PolicyState::Subject(SubjectState {
            subject: self.0.clone(),
            assignments: Vec::new(),
        }))
    }

    fn entry_size(&self, _entry: &CatalogueEntryState) -> usize {
        0
    }
}

#[tokio::test]
async fn a_head_that_holds_the_state_of_another_entity_fails_closed() {
    let machine = BootstrapMachine::new(BootstrapPorts {
        codec: Arc::new(SubjectCodec(SubjectRef::user(
            Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap(),
        ))),
        digest: Arc::new(HashDigest),
    });
    let log = FakePolicyBootstrapLog::with(first_version());

    let failure = not_started(run_bootstrap(machine, &log).await);

    assert_eq!(
        failure,
        BootstrapFailure::UnreadableHead("the record is not a head".to_owned())
    );
}

#[tokio::test]
async fn a_complete_version_above_the_version_its_head_names_fails_closed() {
    let mut records = first_version();
    let mut head = framed_head(4, 2, 2, PolicyDigestValue::ZERO);
    head.record.payload = Some(format!(
        "head 1 {}",
        digest_of(&[(ROLE, "a"), (OTHER, "b")]).to_hex()
    ));
    records.push(row(3, THIRD, "c", 2, (1, 2)));
    records.push(head);
    let log = FakePolicyBootstrapLog::with(records);

    let failure = not_started(run(&log).await);

    assert_eq!(failure, BootstrapFailure::VersionAboveHead { version: 2 });
}
