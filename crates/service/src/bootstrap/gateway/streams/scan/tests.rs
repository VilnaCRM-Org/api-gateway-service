use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use iam_domain::HttpMethod;
use test_support::clock::ManualClock;

use super::*;
use crate::bootstrap::gateway::streams::{
    Grant, Redecision, StreamHandle, StreamRecord, StreamSettings,
};

const IDLE: Duration = Duration::from_secs(60);

#[derive(Debug, Default)]
struct Fence(AtomicBool);

impl StreamFence for Fence {
    fn closed(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Answers each decision with the next verdict of its list, and counts them.
#[derive(Debug)]
struct Decider {
    verdicts: Mutex<Vec<Revalidated>>,
    decided: AtomicUsize,
}

impl Decider {
    fn answering(verdicts: Vec<Revalidated>) -> Arc<Self> {
        Arc::new(Self {
            verdicts: Mutex::new(verdicts),
            decided: AtomicUsize::new(0),
        })
    }

    fn decided(&self) -> usize {
        self.decided.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl Redecision for Decider {
    async fn decide(&self, _grant: &Grant) -> Revalidated {
        self.decided.fetch_add(1, Ordering::SeqCst);
        self.verdicts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
            .unwrap_or(Revalidated::Denied)
    }
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn streams() -> (Arc<Streams>, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::at(at(1_000)));
    let streams = Streams::new(
        StreamSettings {
            idle_timeout: IDLE,
            per_subject: 8,
        },
        Arc::<ManualClock>::clone(&clock),
    );
    (streams, clock)
}

fn open(
    streams: &Streams,
    token_expires_at: Option<SystemTime>,
    assignment_expires_at: Option<SystemTime>,
) -> StreamHandle {
    let record = StreamRecord {
        subject: Some("user-1".to_owned()),
        session: Some("session-1".to_owned()),
        required_keys: vec!["rest:users:GET /api/stream".to_owned()],
        scope: "global".to_owned(),
        token_expires_at,
        assignment_expires_at,
        version: 3,
    };
    let grant = Grant {
        principal: None,
        host: "api.example.test".to_owned(),
        method: HttpMethod::Get,
        path: "/api/stream".to_owned(),
    };
    streams.registry().open(record, grant).unwrap()
}

#[tokio::test]
async fn a_pod_that_may_not_serve_closes_every_stream() {
    let (streams, _clock) = streams();
    let first = open(&streams, None, None);
    let second = open(&streams, None, None);
    let fence = Fence(AtomicBool::new(true));

    streams.scan(&fence).await;

    assert_eq!(first.closed().await, CloseReason::Fenced);
    assert_eq!(second.closed().await, CloseReason::Fenced);
    assert!(streams.registry().is_empty());
}

#[tokio::test]
async fn a_pod_that_may_serve_closes_nothing() {
    let (streams, _clock) = streams();
    let held = open(&streams, Some(at(5_000)), None);

    streams.scan(&Fence::default()).await;

    assert_eq!(streams.registry().len(), 1);
    drop(held);
}

#[tokio::test]
async fn a_stream_ends_when_its_token_expires_on_the_controlled_clock() {
    let (streams, clock) = streams();
    let expiring = open(&streams, Some(at(1_900)), None);
    let lasting = open(&streams, Some(at(9_000)), None);
    streams.scan(&Fence::default()).await;
    assert_eq!(streams.registry().len(), 2);

    clock.advance(Duration::from_mins(15));
    streams.scan(&Fence::default()).await;

    assert_eq!(expiring.closed().await, CloseReason::TokenExpired);
    assert_eq!(streams.registry().len(), 1);
    drop(lasting);
}

#[tokio::test(start_paused = true)]
async fn a_stream_without_traffic_ends_after_the_idle_timeout() {
    let (streams, _clock) = streams();
    let quiet = open(&streams, None, None);
    let busy = open(&streams, None, None);

    tokio::time::advance(IDLE.saturating_sub(Duration::from_secs(1))).await;
    busy.activity().touch();
    streams.scan(&Fence::default()).await;
    assert_eq!(streams.registry().len(), 2);
    tokio::time::advance(Duration::from_secs(2)).await;
    streams.scan(&Fence::default()).await;

    assert_eq!(quiet.closed().await, CloseReason::Idle);
    assert_eq!(streams.registry().len(), 1);
    drop(busy);
}

#[tokio::test]
async fn nothing_is_decided_again_before_the_assignment_expires() {
    let (streams, clock) = streams();
    let decider = Decider::answering(vec![Revalidated::Denied]);
    streams.install(Arc::<Decider>::clone(&decider));
    let held = open(&streams, Some(at(5_000)), Some(at(1_600)));

    clock.advance(Duration::from_secs(599));
    streams.scan(&Fence::default()).await;

    assert_eq!(decider.decided(), 0);
    assert_eq!(streams.registry().len(), 1);
    drop(held);
}

#[tokio::test]
async fn a_stream_that_is_denied_at_the_assignment_expiry_ends() {
    let (streams, clock) = streams();
    streams.install(Decider::answering(vec![Revalidated::Denied]));
    let held = open(&streams, Some(at(5_000)), Some(at(1_600)));

    clock.advance(Duration::from_mins(10));
    streams.scan(&Fence::default()).await;

    assert_eq!(held.closed().await, CloseReason::Revoked);
    assert!(streams.registry().is_empty());
}

#[tokio::test]
async fn a_stream_that_is_still_allowed_stays_with_the_next_expiry() {
    let (streams, clock) = streams();
    let decider = Decider::answering(vec![Revalidated::Allowed {
        next_expiry: Some(at(3_000)),
    }]);
    streams.install(Arc::<Decider>::clone(&decider));
    let held = open(&streams, Some(at(5_000)), Some(at(1_600)));

    clock.advance(Duration::from_mins(10));
    streams.scan(&Fence::default()).await;
    streams.scan(&Fence::default()).await;

    assert_eq!(decider.decided(), 1);
    let record = streams.registry().record(held.id()).unwrap();
    assert_eq!(record.assignment_expires_at, Some(at(3_000)));
}

#[tokio::test]
async fn a_stream_with_a_second_assignment_that_never_expires_is_not_decided_again() {
    let (streams, clock) = streams();
    let decider = Decider::answering(vec![Revalidated::Allowed { next_expiry: None }]);
    streams.install(Arc::<Decider>::clone(&decider));
    let held = open(&streams, Some(at(5_000)), Some(at(1_600)));

    clock.advance(Duration::from_mins(10));
    streams.scan(&Fence::default()).await;
    clock.advance(Duration::from_mins(10));
    streams.scan(&Fence::default()).await;

    assert_eq!(decider.decided(), 1);
    assert_eq!(streams.registry().len(), 1);
    drop(held);
}

#[tokio::test]
async fn without_a_decider_a_stream_at_its_assignment_expiry_ends() {
    let (streams, clock) = streams();
    let held = open(&streams, None, Some(at(1_100)));

    clock.advance(Duration::from_secs(100));
    streams.scan(&Fence::default()).await;

    assert_eq!(held.closed().await, CloseReason::Revoked);
}

#[tokio::test]
async fn the_token_expiry_wins_over_the_assignment_expiry() {
    let (streams, clock) = streams();
    let decider = Decider::answering(vec![Revalidated::Allowed { next_expiry: None }]);
    streams.install(Arc::<Decider>::clone(&decider));
    let held = open(&streams, Some(at(1_100)), Some(at(1_100)));

    clock.advance(Duration::from_secs(100));
    streams.scan(&Fence::default()).await;

    assert_eq!(held.closed().await, CloseReason::TokenExpired);
    assert_eq!(decider.decided(), 0);
}
