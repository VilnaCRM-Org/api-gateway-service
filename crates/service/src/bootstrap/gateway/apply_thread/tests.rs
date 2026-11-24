use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use iam_application::{BootstrapEntry, BootstrapSnapshot};
use iam_domain::{
    LogEpoch, PolicyDigest as _, PolicyDigestValue, PolicyState, PolicyVersion, PolicyView as _,
    StateKey, StateRecordCodec as _, SubjectRef, SubjectState,
};
use iam_infrastructure::{
    ArcSwapPolicySnapshot, JsonStateRecordCodec, MatchitRouteTableCompiler, PUBLISH_INTERVAL,
    PolicySnapshotBuilder, Sha256PolicyDigest, SnapshotPorts,
};
use shared_domain::Uuid;
use test_support::boot_clock::FakeBootClock;
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
