use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use iam_application::{
    ApplyResult, BootstrapEntry, BootstrapSnapshot, DerivedStateChecker, FenceCause,
    FreshnessState, ProofSink as _, TailApplier,
};
use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{
    BootClock as _, DerivedMismatch, FramedRecord, FreshnessRule, LogEpoch, PolicyDigest as _,
    PolicyDigestValue, PolicyHead, PolicyState, PolicyVersion, PolicyView as _, RelayEpoch,
    StateKey, StateRecordCodec as _, SubjectRef, SubjectState, VersionedRecord,
};
use iam_infrastructure::{
    ArcSwapPolicySnapshot, JsonStateRecordCodec, MatchitRouteTableCompiler, PUBLISH_INTERVAL,
    PolicySnapshotBuilder, Sha256PolicyDigest, SnapshotPorts,
};
use shared_domain::Uuid;
use test_support::boot_clock::FakeBootClock;
use test_support::log::LogRecorder;
use tokio::sync::oneshot;

use super::{ApplyError, ApplyThread};

/// The longest a test waits for the apply thread.
const BOUND: Duration = Duration::from_secs(5);

fn version(number: i64) -> PolicyVersion {
    PolicyVersion::new(number).unwrap()
}

fn builder(cell: &Arc<ArcSwapPolicySnapshot>) -> PolicySnapshotBuilder {
    let ports = SnapshotPorts {
        codec: Arc::new(JsonStateRecordCodec),
        digest: Arc::new(Sha256PolicyDigest),
        compiler: Arc::new(MatchitRouteTableCompiler),
        boot_clock: Arc::new(FakeBootClock::new()),
    };
    PolicySnapshotBuilder::new(ports, Arc::clone(cell), PUBLISH_INTERVAL)
}

fn empty_state(number: i64) -> BootstrapSnapshot {
    BootstrapSnapshot {
        version: version(number),
        log_epoch: LogEpoch::ZERO,
        digest: PolicyDigestValue::ZERO,
        entries: Vec::new(),
        incomplete: None,
        tail_from: 0,
        read_to: 0,
    }
}

fn running() -> (ApplyThread, Arc<ArcSwapPolicySnapshot>) {
    let (thread, _death, cell) = watched();
    (thread, cell)
}

/// A running thread with its death channel.
fn watched() -> (
    ApplyThread,
    oneshot::Receiver<()>,
    Arc<ArcSwapPolicySnapshot>,
) {
    let cell = Arc::new(ArcSwapPolicySnapshot::deferred());
    let (thread, death) = ApplyThread::spawn(builder(&cell), Arc::clone(&cell)).unwrap();
    (thread, death, cell)
}

/// Waits, for at most five seconds, until `done` holds.
fn wait_until(mut done: impl FnMut() -> bool) {
    for _ in 0..500 {
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("the wait timed out");
}

fn thread_id(thread: &ApplyThread) -> std::thread::ThreadId {
    let (sender, receiver) = mpsc::channel();
    thread
        .run_on_thread(move |_builder| {
            sender.send(std::thread::current().id()).unwrap();
        })
        .unwrap();
    receiver.recv_timeout(BOUND).unwrap()
}

#[tokio::test]
async fn an_installed_state_is_published_at_its_version() {
    let (thread, cell) = running();

    let applied = thread.install(empty_state(3)).await.unwrap();

    assert_eq!(applied, version(3));
    assert_eq!(cell.current().unwrap().version(), version(3));
    assert!(thread.stop());
}

/// The state of one subject without assignments at `number`, with the digest it hashes to.
fn one_subject(number: i64) -> BootstrapSnapshot {
    let subject = SubjectRef::user(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap());
    let key = StateKey::Subject(subject.clone());
    let payload = JsonStateRecordCodec
        .encode(&PolicyState::Subject(SubjectState {
            subject,
            assignments: Vec::new(),
        }))
        .unwrap();
    let digest = PolicyDigestValue::ZERO.combined(Sha256PolicyDigest.entity_hash(&key, &payload));
    BootstrapSnapshot {
        entries: vec![BootstrapEntry {
            key,
            version: version(number),
            payload,
        }],
        digest,
        ..empty_state(number)
    }
}

#[tokio::test]
async fn the_entries_of_an_installed_state_are_published_with_its_digest() {
    let (thread, cell) = running();
    let state = one_subject(4);
    let digest = state.digest;

    let applied = thread.install(state).await.unwrap();

    assert_eq!(applied, version(4));
    let snapshot = cell.current().unwrap();
    assert_eq!(snapshot.version(), version(4));
    assert_eq!(snapshot.digest(), digest);
    assert_ne!(digest, PolicyDigestValue::ZERO);
    assert!(thread.stop());
}

#[tokio::test]
async fn a_state_that_does_not_hash_to_its_head_is_refused_and_not_published() {
    let (thread, cell) = running();
    let mut state = empty_state(2);
    state.digest = PolicyDigestValue::from_bytes([7; PolicyDigestValue::LENGTH]);

    let refused = thread.install(state).await;

    assert!(matches!(refused, Err(ApplyError::Refused(_))));
    assert!(cell.current().is_none());
    assert!(thread.stop());
}

#[tokio::test]
async fn the_last_reference_to_a_retired_snapshot_is_freed_on_the_apply_thread() {
    let (thread, cell) = running();
    thread.install(empty_state(1)).await.unwrap();
    let held = cell.current().unwrap();
    thread.install(empty_state(2)).await.unwrap();
    assert_eq!(
        cell.retired(),
        1,
        "a request still reads the replaced snapshot"
    );

    drop(held);

    wait_until(|| cell.retired() == 0);
    assert_eq!(cell.last_reclaimed_on(), Some(thread_id(&thread)));
    assert_ne!(cell.last_reclaimed_on(), Some(std::thread::current().id()));
    assert!(thread.stop());
}

#[tokio::test]
async fn a_panic_on_the_apply_thread_is_reported_as_its_death() {
    let (thread, death, _cell) = watched();

    thread
        .run_on_thread(|_builder| panic!("injected panic of the apply thread"))
        .unwrap();

    let died = tokio::time::timeout(BOUND, death).await.unwrap();
    assert_eq!(died, Ok(()));
    assert!(matches!(
        thread.install(empty_state(1)).await,
        Err(ApplyError::Gone)
    ));
    assert!(!thread.stop(), "the thread ended by a panic");
}

#[tokio::test]
async fn a_clean_stop_is_not_a_death() {
    let (thread, death, _cell) = watched();

    assert!(thread.stop());

    let outcome = tokio::time::timeout(BOUND, death).await.unwrap();
    assert!(outcome.is_err(), "the notice is never sent");
}

#[tokio::test]
async fn the_death_channel_stays_pending_while_the_thread_runs() {
    let (thread, mut death, _cell) = watched();

    assert_eq!(death.try_recv(), Err(oneshot::error::TryRecvError::Empty));
    assert!(thread.stop());
}

#[tokio::test]
async fn dropping_the_handle_ends_the_thread_without_a_death_notice() {
    let (thread, death, _cell) = watched();

    drop(thread);

    let outcome = tokio::time::timeout(BOUND, death).await.unwrap();
    assert!(outcome.is_err());
}

/// The subject that the batches of the tail write, with its canonical payload.
fn tail_subject() -> (StateKey, String) {
    let subject = SubjectRef::user(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890cd").unwrap());
    let payload = JsonStateRecordCodec
        .encode(&PolicyState::Subject(SubjectState {
            subject: subject.clone(),
            assignments: Vec::new(),
        }))
        .unwrap();
    (StateKey::Subject(subject), payload)
}

/// A record at `offset`: row `seq` of `count` of `number`, with the digest after it.
fn framed(
    offset: i64,
    (key, payload): (StateKey, Option<String>),
    number: i64,
    (seq, count): (u32, u32),
    digest_after: PolicyDigestValue,
) -> FramedRecord {
    FramedRecord {
        offset,
        record: VersionedRecord {
            key,
            payload,
            version: version(number),
            seq,
            count,
            digest_after,
            log_epoch: LogEpoch::new(1).unwrap(),
            relay_epoch: RelayEpoch::new(1).unwrap(),
        },
    }
}

/// The digest of the state after the subject of [`tail_subject`] is written.
fn subject_digest() -> PolicyDigestValue {
    let (key, payload) = tail_subject();
    PolicyDigestValue::ZERO.combined(Sha256PolicyDigest.entity_hash(&key, &payload))
}

fn subject_row(offset: i64, number: i64, digest_after: PolicyDigestValue) -> FramedRecord {
    let (key, payload) = tail_subject();
    framed(offset, (key, Some(payload)), number, (1, 2), digest_after)
}

/// The head of `number` that names `digest`, with `digest_after` as its framing digest.
fn head_row(
    offset: i64,
    number: i64,
    digest: PolicyDigestValue,
    digest_after: PolicyDigestValue,
) -> FramedRecord {
    let payload = JsonStateRecordCodec
        .encode(&PolicyState::Head(PolicyHead {
            version: version(number),
            digest,
        }))
        .unwrap();
    framed(
        offset,
        (StateKey::Head, Some(payload)),
        number,
        (2, 2),
        digest_after,
    )
}

/// A thread with the empty state of version 3 under log epoch 1 installed.
async fn installed() -> (ApplyThread, Arc<ArcSwapPolicySnapshot>) {
    let (thread, cell) = running();
    let state = BootstrapSnapshot {
        log_epoch: LogEpoch::new(1).unwrap(),
        ..empty_state(3)
    };
    thread.install(state).await.unwrap();
    (thread, cell)
}

#[tokio::test]
async fn a_complete_version_of_the_tail_is_applied_through_the_tail_port() {
    let (thread, cell) = installed().await;
    let digest = subject_digest();

    let result = TailApplier::apply(
        &thread,
        vec![
            subject_row(10, 4, digest),
            subject_row(10, 4, digest),
            head_row(11, 4, digest, digest),
        ],
    )
    .await;

    assert_eq!(result, ApplyResult::Applied);
    thread
        .run_on_thread(|builder| {
            builder.flush();
        })
        .unwrap();
    wait_until(|| {
        cell.current()
            .is_some_and(|snapshot| snapshot.version() == version(4))
    });
    assert_eq!(cell.current().unwrap().digest(), digest);
    assert!(thread.stop());
}

#[tokio::test]
async fn a_version_that_is_not_complete_is_held_and_nothing_is_published() {
    let (thread, cell) = installed().await;

    let result = thread
        .apply_batch(vec![subject_row(10, 4, subject_digest())])
        .await;

    assert_eq!(result, ApplyResult::Applied);
    assert_eq!(cell.current().unwrap().version(), version(3));
    assert!(thread.stop());
}

#[tokio::test]
async fn each_fault_of_the_log_fences_the_batch() {
    let digest = subject_digest();
    let other = PolicyDigestValue::from_bytes([9; PolicyDigestValue::LENGTH]);
    let (key, payload) = tail_subject();
    let mut conflicting = subject_row(11, 4, digest);
    conflicting.record.payload = Some(format!("{payload} "));
    let mut lower_epoch = subject_row(10, 4, digest);
    lower_epoch.record.log_epoch = LogEpoch::ZERO;
    let cases = [
        (
            vec![framed(
                10,
                (key.clone(), Some(payload.clone())),
                4,
                (3, 2),
                digest,
            )],
            FenceCause::Malformed { offset: 10 },
        ),
        (
            vec![subject_row(10, 6, digest)],
            FenceCause::Gap { expected: 4 },
        ),
        (
            vec![subject_row(10, 4, digest), conflicting],
            FenceCause::ConflictingContent,
        ),
        (vec![lower_epoch], FenceCause::LowerLogEpoch),
        (
            vec![subject_row(10, 4, digest), head_row(11, 4, digest, other)],
            FenceCause::DigestMismatch { version: 4 },
        ),
    ];

    for (records, cause) in cases {
        let (thread, cell) = installed().await;

        let result = thread.apply_batch(records).await;

        assert_eq!(result, ApplyResult::Fenced(cause));
        assert_eq!(cell.current().unwrap().version(), version(3));
        assert!(thread.stop());
    }
}

#[tokio::test]
async fn a_version_without_its_head_is_unappliable() {
    let (thread, cell) = installed().await;
    let digest = subject_digest();
    let (key, payload) = tail_subject();

    let result = thread
        .apply_batch(vec![
            subject_row(10, 4, digest),
            framed(11, (key, Some(payload)), 4, (2, 2), digest),
        ])
        .await;

    assert!(
        matches!(result, ApplyResult::Fenced(FenceCause::Unappliable(_))),
        "{result:?}"
    );
    assert_eq!(cell.current().unwrap().version(), version(3));
    assert!(thread.stop());
}

#[tokio::test]
async fn a_batch_for_a_thread_that_died_finds_it_gone() {
    let (thread, death, _cell) = watched();
    thread
        .run_on_thread(|_builder| panic!("injected panic of the apply thread"))
        .unwrap();
    tokio::time::timeout(BOUND, death).await.unwrap().unwrap();
    wait_until(|| thread.run_on_thread(|_builder| {}).is_err());

    let result = thread.apply_batch(Vec::new()).await;

    assert_eq!(result, ApplyResult::Gone);
    assert!(!thread.stop());
}

const CHECK_INTERVAL: Duration = Duration::from_secs(1);

/// A thread that checks the derived structures every second of a clock the test moves.
fn checked() -> (ApplyThread, Arc<FakeBootClock>, Arc<ArcSwapPolicySnapshot>) {
    let clock = Arc::new(FakeBootClock::new());
    let cell = Arc::new(ArcSwapPolicySnapshot::deferred());
    let ports = SnapshotPorts {
        codec: Arc::new(JsonStateRecordCodec),
        digest: Arc::new(Sha256PolicyDigest),
        compiler: Arc::new(MatchitRouteTableCompiler),
        boot_clock: Arc::<FakeBootClock>::clone(&clock),
    };
    let builder = PolicySnapshotBuilder::new(ports, Arc::clone(&cell), PUBLISH_INTERVAL);
    let (thread, _death) = ApplyThread::spawn_checked(
        builder,
        Arc::clone(&cell),
        Some(DerivedStateChecker::new(CHECK_INTERVAL)),
    )
    .unwrap();
    (thread, clock, cell)
}

fn subject_key() -> StateKey {
    StateKey::Subject(SubjectRef::user(
        Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap(),
    ))
}

/// Moves the clock one interval at a time, for at most a full rotation and one more, until the
/// snapshot is withdrawn; whether it was.
fn run_rotation(clock: &FakeBootClock, cell: &ArcSwapPolicySnapshot) -> bool {
    for _ in 0..18 {
        clock.advance(CHECK_INTERVAL);
        for _ in 0..40 {
            if cell.current().is_none() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    false
}

#[tokio::test]
async fn a_consistent_state_survives_a_full_rotation_of_checks() {
    let (thread, clock, cell) = checked();
    thread.install(one_subject(4)).await.unwrap();

    let withdrawn = run_rotation(&clock, &cell);

    assert!(!withdrawn);
    assert_eq!(cell.current().unwrap().version(), version(4));
    assert_eq!(thread.fault(), None);
    assert!(thread.stop());
}

#[tokio::test]
async fn a_corrupt_structure_withdraws_the_snapshot_and_reports_the_fault_once() {
    let (thread, clock, cell) = checked();
    thread.install(one_subject(4)).await.unwrap();
    let healthy = cell.current().unwrap().derived_hash();
    let key = subject_key();
    thread
        .run_on_thread(move |builder| assert!(builder.corrupt_derived(&key)))
        .unwrap();
    wait_until(|| {
        cell.current()
            .is_some_and(|snapshot| snapshot.derived_hash() != healthy)
    });

    let withdrawn = run_rotation(&clock, &cell);

    assert!(withdrawn, "no snapshot may serve a wrong structure");
    let fault = thread.fault();
    assert!(matches!(fault, Some(FenceCause::DerivedMismatch { .. })));
    assert_eq!(thread.fault(), None, "the fault is reported once");
    assert!(thread.stop());
}

#[tokio::test]
async fn after_a_mismatch_nothing_is_applied_or_published_until_a_state_is_installed() {
    let (thread, clock, cell) = checked();
    thread.install(one_subject(4)).await.unwrap();
    let key = subject_key();
    thread
        .run_on_thread(move |builder| assert!(builder.corrupt_derived(&key)))
        .unwrap();
    assert!(run_rotation(&clock, &cell));

    let refused = thread.apply_batch(Vec::new()).await;
    clock.advance(Duration::from_secs(30));
    std::thread::sleep(Duration::from_millis(150));

    assert!(matches!(
        refused,
        ApplyResult::Fenced(FenceCause::DerivedMismatch { .. })
    ));
    assert!(cell.current().is_none(), "nothing is published again");

    thread.install(one_subject(5)).await.unwrap();

    assert_eq!(cell.current().unwrap().version(), version(5));
    assert_eq!(thread.fault(), None, "the install lifted the fault");
    assert!(matches!(
        thread.apply_batch(Vec::new()).await,
        ApplyResult::Applied
    ));
    assert!(thread.stop());
}

#[tokio::test]
async fn a_thread_without_a_checker_never_withdraws_or_reports_anything() {
    let (thread, cell) = running();
    thread.install(one_subject(4)).await.unwrap();
    let key = subject_key();
    thread
        .run_on_thread(move |builder| assert!(builder.corrupt_derived(&key)))
        .unwrap();
    std::thread::sleep(Duration::from_millis(150));

    assert!(cell.current().is_some());
    assert_eq!(thread.fault(), None);
    assert!(thread.stop());
}

#[tokio::test]
async fn a_proof_offered_to_the_thread_is_attached_once_the_state_covers_it() {
    let cell = Arc::new(ArcSwapPolicySnapshot::deferred());
    let clock = Arc::new(FakeBootClock::new());
    let state = Arc::new(FreshnessState::new(
        FreshnessRule::new(Duration::from_secs(15), Duration::from_secs(2)),
        Arc::<FakeBootClock>::clone(&clock),
    ));
    let (thread, _death) = ApplyThread::spawn_proving(
        builder(&cell),
        Arc::clone(&cell),
        None,
        Some(Arc::clone(&state)),
    )
    .unwrap();
    let mut installed = empty_state(3);
    installed.tail_from = 3;
    installed.read_to = 3;
    thread.install(installed).await.unwrap();
    assert!(!state.is_fresh());

    thread.offer(FreshnessProof {
        taken_at: clock.now(),
        watermark: 3,
    });

    wait_until(|| state.is_fresh());
    assert!(thread.stop());
}

#[test]
fn a_mismatch_is_logged_with_its_shard_and_both_hashes() {
    let (recorder, _guard) = LogRecorder::install();

    super::log_mismatch(&DerivedMismatch {
        shard: 9,
        rebuilt: PolicyDigestValue::ZERO,
        held: PolicyDigestValue::ZERO,
    });

    let lines = recorder.lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].field("metric"), Some("policy_derived_mismatch"));
    assert_eq!(lines[0].field("shard"), Some("9"));
    assert_eq!(
        lines[0].field("rebuilt"),
        Some(PolicyDigestValue::ZERO.to_hex().as_str())
    );
}
