//! The check of the derived structures of a gateway pod against the raw records (Story 9.6), on
//! the compose broker. The pods run on a boot clock the test moves, so every check interval is a
//! step of that clock.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use iam_domain::{
    AssignmentScope, AssignmentState, EntityVersion, GrantState, LogEpoch, OutboxKind, OutboxRow,
    PolicyDigestValue, PolicyState, PolicyVersion, PolicyView as _, RoleId, RoleKind, RoleState,
    StateBatch, StateChange, StateKey, SubjectRef, SubjectState,
};
use iam_infrastructure::{JsonStateRecordCodec, KrafkaPolicyLogTail, Sha256PolicyDigest};
use shared_domain::{Uuid, UuidGenerator as _};
use shared_infrastructure::clock::SystemClock;
use shared_infrastructure::id::UuidV7Generator;
use test_support::boot_clock::FakeBootClock;
use test_support::rng::FakeRng;
use test_support::topic_inspector::FakeTopicInspector;
use tokio::sync::watch;

use crate::gateway_bootstrap::{BOUND, adapters_on, publish, serves, settings, unique_topic};
use service::bootstrap::gateway::apply_thread::ApplyThread;
use service::bootstrap::gateway::policy::{
    PolicyAdapters, TailAdapters, TailSettings, start_policy_with_thread,
};
use service::bootstrap::{TaskMode, TaskStop, TaskSupervisor};

const INTERVAL: Duration = Duration::from_secs(1);

fn uuid(last: u8) -> Uuid {
    Uuid::parse(&format!("0192f6a0-0000-7000-8000-0000000000{last:02x}")).unwrap()
}

fn role_key() -> StateKey {
    StateKey::Role(RoleId::from_uuid(uuid(1)))
}

fn subject_ref() -> SubjectRef {
    SubjectRef::user(uuid(2))
}

fn role_state() -> PolicyState {
    PolicyState::Role(RoleState {
        id: RoleId::from_uuid(uuid(1)),
        name: "editor".to_owned(),
        description: None,
        kind: RoleKind::Custom,
        version: EntityVersion::INITIAL,
        grants: vec![GrantState {
            key: "rest:cat-0:GET /users".to_owned(),
            active: true,
        }],
    })
}

fn subject_state() -> PolicyState {
    PolicyState::Subject(
        SubjectState {
            subject: subject_ref(),
            assignments: vec![AssignmentState {
                role: RoleId::from_uuid(uuid(1)),
                scope: AssignmentScope::Global,
                expires_at_micros: None,
            }],
        }
        .canonical(),
    )
}

/// The rows of version 1 of a policy with one role and one subject that holds it, as the outbox
/// writes them, with the digests the pod verifies.
fn first_version(topic: &str) -> Vec<OutboxRow> {
    let changes = [
        (role_key(), role_state()),
        (StateKey::Subject(subject_ref()), subject_state()),
    ]
    .into_iter()
    .map(|(key, after)| StateChange {
        key,
        before: None,
        after: Some(after),
    });
    let version = PolicyVersion::new(1).unwrap();
    let batch = StateBatch::assemble(
        version,
        PolicyDigestValue::ZERO,
        changes,
        (&JsonStateRecordCodec, &Sha256PolicyDigest),
    )
    .unwrap();
    batch
        .rows()
        .iter()
        .map(|row| OutboxRow {
            id: UuidV7Generator.generate(),
            kind: OutboxKind::State,
            topic: topic.to_owned(),
            record_key: row.key().to_string(),
            payload: row.payload().map(str::to_owned),
            policy_version: version,
            seq: Some(row.seq()),
            count: Some(row.count()),
            digest_after: Some(row.digest_after()),
            log_epoch: LogEpoch::new(0).unwrap(),
            event_type: None,
        })
        .collect()
}

/// A pod that follows `topic` on `clock`, checking a group of shards every [`INTERVAL`] of it.
fn pod(topic: &str, clock: &Arc<FakeBootClock>) -> (PolicyAdapters, Arc<AtomicUsize>) {
    let boot_clock: Arc<dyn iam_domain::BootClock> = Arc::<FakeBootClock>::clone(clock);
    let (adapters, captures) = adapters_on(topic, boot_clock);
    let mut tail_settings = settings(topic);
    tail_settings.client_id = "iam-gateway-integration".to_owned();
    let adapters = adapters.following(TailAdapters {
        log: Arc::new(KrafkaPolicyLogTail::tail(
            tail_settings,
            Duration::from_millis(100),
        )),
        inspector: Arc::new(FakeTopicInspector::passing()),
        clock: Arc::new(SystemClock),
        rng: Arc::new(FakeRng::seeded(1)),
        settings: TailSettings {
            retry_delay: Duration::from_millis(100),
            ready_bound: Duration::from_millis(200),
            hard_bound: Duration::from_secs(15),
            derived_check_interval: INTERVAL,
        },
    });
    (adapters, captures)
}

/// A running pod: its adapters, the handle to its apply thread and the way to stop it.
struct Running {
    adapters: PolicyAdapters,
    captures: Arc<AtomicUsize>,
    thread: Arc<ApplyThread>,
    stop: watch::Sender<bool>,
    tasks: TaskSupervisor,
}

async fn start(topic: &str, clock: &Arc<FakeBootClock>) -> Running {
    let (adapters, captures) = pod(topic, clock);
    let (stop, stopping) = watch::channel(false);
    let mut tasks = TaskSupervisor::new(TaskMode::Test, stopping);
    let (_death, thread) = start_policy_with_thread(&adapters, &mut tasks).unwrap();
    serves(&adapters, 1).await;
    Running {
        adapters,
        captures,
        thread,
        stop,
        tasks,
    }
}

impl Running {
    fn digest_events(&self) -> (PolicyVersion, PolicyDigestValue, PolicyDigestValue) {
        let snapshot = self.adapters.cell.current().expect("a published snapshot");
        (
            snapshot.version(),
            snapshot.digest(),
            snapshot.derived_hash(),
        )
    }

    /// Moves the clock one interval at a time, waiting for the apply thread to take each step,
    /// until `done` holds or the rotation and one more interval have passed; whether it held.
    async fn rotate(&self, clock: &FakeBootClock, mut done: impl FnMut() -> bool) -> bool {
        for _ in 0..18 {
            clock.advance(INTERVAL);
            for _ in 0..30 {
                if done() {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        done()
    }

    fn corrupt_role(&self) {
        let (done, finished) = mpsc::channel();
        self.thread
            .run_on_thread(move |builder| {
                assert!(builder.corrupt_derived(&role_key()));
                done.send(()).unwrap();
            })
            .unwrap();
        finished.recv_timeout(BOUND).unwrap();
    }

    async fn shut_down(self) {
        self.stop.send_replace(true);
        let Self { tasks, thread, .. } = self;
        assert_eq!(tasks.stop(BOUND).await, TaskStop::Drained);
        drop(thread);
    }
}

async fn topic_with_first_version() -> String {
    let topic = unique_topic();
    publish(&topic, &first_version(&topic)).await;
    topic
}

#[tokio::test]
async fn a_consistent_snapshot_is_never_fenced_in_sixteen_check_intervals() {
    let topic = topic_with_first_version().await;
    let clock = Arc::new(FakeBootClock::new());
    let pod = start(&topic, &clock).await;
    let before = pod.digest_events();

    let fenced = pod
        .rotate(&clock, || pod.adapters.cell.current().is_none())
        .await;

    assert!(!fenced, "a consistent snapshot was withdrawn");
    assert_eq!(pod.digest_events(), before);
    assert_eq!(pod.captures.load(Ordering::SeqCst), 1, "no rebootstrap");
    pod.shut_down().await;
}

#[tokio::test]
async fn a_corrupt_structure_fences_the_pod_which_withdraws_its_snapshot_and_rebootstraps() {
    let topic = topic_with_first_version().await;
    let clock = Arc::new(FakeBootClock::new());
    let pod = start(&topic, &clock).await;
    let (version, digest, healthy) = pod.digest_events();

    pod.corrupt_role();
    let (_, corrupt_digest, corrupt_hash) = pod.digest_events();
    let withdrawn = pod
        .rotate(&clock, || pod.adapters.cell.current().is_none())
        .await;

    assert_eq!(corrupt_digest, digest, "the raw records did not change");
    assert_ne!(corrupt_hash, healthy, "policy_derived_hash_info changes");
    assert!(
        withdrawn,
        "the snapshot with a wrong structure kept serving"
    );
    let rebootstrapped = tokio::time::timeout(BOUND, async {
        while pod.adapters.cell.current().is_none() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(rebootstrapped.is_ok(), "the pod did not rebootstrap");
    assert_eq!(pod.digest_events(), (version, digest, healthy));
    assert_eq!(pod.captures.load(Ordering::SeqCst), 2);
    pod.shut_down().await;
}

#[tokio::test]
async fn no_request_reads_a_snapshot_between_the_mismatch_and_the_rebootstrap() {
    let topic = topic_with_first_version().await;
    let clock = Arc::new(FakeBootClock::new());
    let pod = start(&topic, &clock).await;
    pod.corrupt_role();

    let withdrawn = pod
        .rotate(&clock, || pod.adapters.cell.current().is_none())
        .await;

    assert!(withdrawn);
    // The cell is what the public listener and the decision API read: no snapshot is 503
    // `iam_stale` and `deny` with reason `unavailable`.
    assert!(pod.adapters.cell.current().is_none());
    pod.shut_down().await;
}

#[tokio::test]
async fn two_pods_with_the_same_history_report_equal_events_until_one_is_corrupted() {
    let topic = topic_with_first_version().await;
    let (first_clock, second_clock) = (
        Arc::new(FakeBootClock::new()),
        Arc::new(FakeBootClock::new()),
    );
    let first = start(&topic, &first_clock).await;
    let second = start(&topic, &second_clock).await;

    assert_eq!(first.digest_events(), second.digest_events());

    first.corrupt_role();

    let (version, digest, hash) = first.digest_events();
    let (second_version, second_digest, second_hash) = second.digest_events();
    assert_eq!((version, digest), (second_version, second_digest));
    assert_ne!(hash, second_hash);
    first.shut_down().await;
    second.shut_down().await;
}

#[tokio::test]
async fn a_request_reads_the_published_snapshot_while_the_apply_thread_is_busy_checking() {
    let topic = topic_with_first_version().await;
    let clock = Arc::new(FakeBootClock::new());
    let pod = start(&topic, &clock).await;
    pod.thread
        .run_on_thread(|_builder| std::thread::sleep(Duration::from_millis(500)))
        .unwrap();

    let started = tokio::time::Instant::now();
    let snapshot = pod.adapters.cell.current();

    assert!(snapshot.is_some());
    assert!(
        started.elapsed() < Duration::from_millis(200),
        "the read waited for the thread"
    );
    pod.shut_down().await;
}
