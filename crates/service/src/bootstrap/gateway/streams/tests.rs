use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{BootClock as _, BootInstant, FreshnessRule, HttpMethod, PolicyVersion};
use test_support::boot_clock::FakeBootClock;
use test_support::clock::FixedClock;
use test_support::gateway_snapshot::{CountingPolicyView, GatewaySnapshot};

use super::*;

const HARD_BOUND: Duration = Duration::from_secs(15);

#[derive(Debug, Default)]
struct Fence(AtomicBool);

impl StreamFence for Fence {
    fn closed(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

fn streams() -> Arc<Streams> {
    Streams::new(
        StreamSettings {
            idle_timeout: Duration::from_mins(5),
            per_subject: 2,
        },
        Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
    )
}

fn open(streams: &Streams, subject: &str) -> Result<StreamHandle, SubjectAtCap> {
    let record = StreamRecord {
        subject: Some(subject.to_owned()),
        session: None,
        required_keys: Vec::new(),
        scope: "global".to_owned(),
        token_expires_at: None,
        assignment_expires_at: None,
        version: 1,
        route: None,
        service: None,
    };
    let grant = Grant {
        principal: None,
        host: "api.example.test".to_owned(),
        method: HttpMethod::Get,
        path: "/events".to_owned(),
    };
    streams.registry().open(record, grant)
}

fn freshness(boot: &Arc<FakeBootClock>) -> Arc<FreshnessState> {
    let state = Arc::new(FreshnessState::new(
        FreshnessRule::new(HARD_BOUND, Duration::from_secs(2)),
        Arc::<FakeBootClock>::clone(boot),
    ));
    state.attach(
        FreshnessProof {
            taken_at: boot.now(),
            watermark: 1,
        },
        PolicyVersion::new(7).unwrap(),
    );
    state
}

fn boot() -> Arc<FakeBootClock> {
    Arc::new(FakeBootClock::starting_at(BootInstant::from_elapsed(
        Duration::from_secs(100),
    )))
}

fn serving() -> Arc<dyn PolicyView> {
    Arc::new(CountingPolicyView::serving(GatewaySnapshot::at(
        PolicyVersion::new(7).unwrap(),
    )))
}

#[test]
fn the_settings_name_the_idle_timeout_and_the_subject_cap() {
    let streams = streams();

    let first = open(&streams, "user-1").unwrap();
    let second = open(&streams, "user-1").unwrap();

    assert!(open(&streams, "user-1").is_err());
    assert!(open(&streams, "user-2").is_ok());
    drop((first, second));
}

#[test]
fn the_streams_hand_out_their_clock_and_their_registry() {
    let streams = streams();

    assert_eq!(streams.now(), SystemTime::UNIX_EPOCH);
    assert_eq!(streams.clock().now(), SystemTime::UNIX_EPOCH);
    assert!(streams.registry().is_empty());
}

#[test]
fn a_fresh_pod_with_a_snapshot_keeps_its_streams() {
    let boot = boot();
    let fence = PodFence::new(serving(), freshness(&boot));

    assert!(!fence.closed());
}

#[test]
fn a_pod_without_a_snapshot_has_fenced() {
    let boot = boot();
    let view: Arc<dyn PolicyView> = Arc::new(CountingPolicyView::empty());
    let fence = PodFence::new(view, freshness(&boot));

    assert!(fence.closed());
}

#[test]
fn a_pod_whose_proof_outlived_the_hard_bound_may_not_serve() {
    let boot = boot();
    let fence = PodFence::new(serving(), freshness(&boot));

    boot.advance(HARD_BOUND.saturating_add(Duration::from_secs(1)));

    assert!(fence.closed());
}

#[tokio::test(start_paused = true)]
async fn the_watch_scans_on_every_tick_and_stops_with_the_flag() {
    let streams = streams();
    let held = open(&streams, "user-1").unwrap();
    let fence = Arc::new(Fence::default());
    let (stop, stopping) = watch::channel(false);
    let watching = tokio::spawn(Arc::clone(&streams).watch(Arc::<Fence>::clone(&fence), stopping));

    tokio::time::sleep(SCAN_INTERVAL.saturating_mul(3)).await;
    assert_eq!(streams.registry().len(), 1);
    fence.0.store(true, Ordering::SeqCst);
    tokio::time::sleep(SCAN_INTERVAL.saturating_mul(2)).await;

    assert_eq!(held.closed().await, CloseReason::Fenced);
    stop.send_replace(true);
    watching.await.unwrap();
}

#[test]
fn the_number_of_open_streams_is_reported_only_when_it_changes() {
    let streams = streams();
    let held = open(&streams, "user-1").unwrap();

    assert_eq!(streams.report(0), 1);
    assert_eq!(streams.report(1), 1);
    drop(held);
    assert_eq!(streams.report(1), 0);
}

/// A decider whose published version and verdict a test sets.
#[derive(Debug)]
struct Published {
    version: Option<i64>,
    allow: AtomicBool,
    decided: AtomicUsize,
}

impl Published {
    fn at(version: Option<i64>, allow: bool) -> Arc<Self> {
        Arc::new(Self {
            version,
            allow: AtomicBool::new(allow),
            decided: AtomicUsize::new(0),
        })
    }

    fn decided(&self) -> usize {
        self.decided.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl Redecision for Published {
    async fn decide(&self, _grant: &Grant) -> Revalidated {
        self.decided.fetch_add(1, Ordering::SeqCst);
        if self.allow.load(Ordering::SeqCst) {
            Revalidated::Allowed { next_expiry: None }
        } else {
            Revalidated::Denied
        }
    }

    fn published(&self) -> Option<i64> {
        self.version
    }
}

fn pronounced(version: i64) -> PolicyVersion {
    PolicyVersion::new(version).unwrap()
}

#[tokio::test]
async fn a_stream_authorized_below_the_published_version_is_decided_at_once_and_closed_when_denied()
{
    let streams = streams();
    let decider = Published::at(Some(8), false);
    streams.install(Arc::<Published>::clone(&decider));
    let held = open(&streams, "user-1").unwrap();

    streams.admit(held.id()).await;

    assert_eq!(held.closed().await, CloseReason::Revoked);
    assert_eq!(decider.decided(), 1);
    assert!(streams.registry().is_empty());
}

#[tokio::test]
async fn a_stream_the_published_version_still_allows_stays_open_and_counts_as_decided() {
    let streams = streams();
    let decider = Published::at(Some(8), true);
    streams.install(Arc::<Published>::clone(&decider));
    let held = open(&streams, "user-1").unwrap();
    assert_eq!(streams.lagging(pronounced(8)), vec![held.id()]);

    streams.admit(held.id()).await;

    assert_eq!(streams.registry().len(), 1);
    assert_eq!(streams.lagging(pronounced(8)), Vec::<u64>::new());
    assert_eq!(decider.decided(), 1);
}

#[tokio::test]
async fn a_stream_authorized_on_the_published_version_is_not_decided_again() {
    let streams = streams();
    let decider = Published::at(Some(1), false);
    streams.install(Arc::<Published>::clone(&decider));
    let held = open(&streams, "user-1").unwrap();

    streams.admit(held.id()).await;

    assert_eq!(decider.decided(), 0);
    assert_eq!(streams.registry().len(), 1);
    assert_eq!(streams.lagging(pronounced(1)), Vec::<u64>::new());
}

#[tokio::test]
async fn without_a_published_version_the_registration_check_decides_nothing() {
    let streams = streams();
    let decider = Published::at(None, false);
    streams.install(Arc::<Published>::clone(&decider));
    let held = open(&streams, "user-1").unwrap();

    streams.admit(held.id()).await;

    assert_eq!(decider.decided(), 0);
    assert_eq!(streams.registry().len(), 1);
}

#[tokio::test]
async fn deciding_a_stream_again_without_a_decider_closes_it() {
    let streams = streams();
    let held = open(&streams, "user-1").unwrap();

    streams.reevaluate(held.id(), pronounced(2)).await;

    assert_eq!(held.closed().await, CloseReason::Revoked);
}

#[tokio::test]
async fn deciding_a_stream_that_is_gone_changes_nothing() {
    let streams = streams();
    let decider = Published::at(Some(2), false);
    streams.install(Arc::<Published>::clone(&decider));

    streams.reevaluate(99, pronounced(2)).await;

    assert_eq!(decider.decided(), 0);
}

#[tokio::test]
async fn the_record_moves_once_every_stream_is_decided_against_the_version() {
    let streams = streams();
    streams.install(Published::at(Some(1), true));
    let board = ReevaluationBoard::new();
    let early = open(&streams, "user-1").unwrap();
    streams.admit(early.id()).await;
    let mark = streams.mark();
    let waiting = open(&streams, "user-2").unwrap();

    streams.settle(mark, pronounced(2));

    assert_eq!(
        streams.lagging(pronounced(2)),
        vec![waiting.id()],
        "the stream that is still waiting for its first check is not settled"
    );
    assert!(!streams.finish(pronounced(2), &board));
    assert_eq!(board.finished(), -1);
    streams.reevaluate(waiting.id(), pronounced(2)).await;
    assert!(streams.finish(pronounced(2), &board));
    assert_eq!(board.finished(), 2);
}

#[tokio::test]
async fn the_streams_of_a_scope_come_from_the_registry() {
    let streams = streams();
    let first = open(&streams, "user-1").unwrap();
    let second = open(&streams, "user-2").unwrap();
    let scope = StreamScope {
        subjects: ["user-2".to_owned()].into(),
        ..StreamScope::default()
    };

    assert_eq!(streams.select(&scope), vec![second.id()]);
    assert_eq!(
        streams.select(&StreamScope {
            everything: true,
            ..StreamScope::default()
        }),
        vec![first.id(), second.id()]
    );
}
