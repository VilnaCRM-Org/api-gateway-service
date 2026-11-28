use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use iam_domain::{PolicyChange, PolicyTouch, PolicyVersion, RoleId, StateKey, SubjectRef};
use shared_domain::Uuid;
use test_support::gateway_snapshot::{CountingPolicyView, GatewaySnapshot};
use test_support::policy_view::FakePolicyView;

use super::*;

const ROLE: &str = "0192f6a0-0000-7000-8000-000000000001";
const ROUTE: &str = "0192f6a0-0000-7000-8000-000000000003";

fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

fn user(number: u32) -> Uuid {
    Uuid::parse(&format!("0192f6a0-0000-7000-8000-{number:012x}")).unwrap()
}

fn touching(keys: &[String]) -> PolicyTouch {
    let mut touch = PolicyTouch::nothing();
    for text in keys {
        touch.note(&StateKey::parse(text).unwrap());
    }
    touch
}

fn change(at: i64, keys: &[String]) -> PolicyChange {
    PolicyChange {
        version: version(at),
        touch: touching(keys),
    }
}

fn subject_key(number: u32) -> String {
    format!("subject/user/{}", user(number))
}

#[derive(Debug, Clone)]
struct Stream {
    id: u64,
    subject: String,
    session: Option<String>,
    route: String,
    service: String,
    evaluated: i64,
    pending: bool,
}

#[derive(Debug, Default)]
struct Registry {
    streams: Vec<Stream>,
    decided: Vec<(u64, i64)>,
}

/// An open-streams double: it records which streams were decided again.
#[derive(Debug, Default)]
struct Streams {
    state: Mutex<Registry>,
}

impl Streams {
    fn with<T>(&self, read: impl FnOnce(&mut Registry) -> T) -> T {
        read(&mut self.state.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn open(&self, subject: &str, session: Option<&str>, route: &str, service: &str) -> u64 {
        self.with(|registry| {
            let id = u64::try_from(registry.streams.len()).unwrap();
            registry.streams.push(Stream {
                id,
                subject: subject.to_owned(),
                session: session.map(str::to_owned),
                route: route.to_owned(),
                service: service.to_owned(),
                evaluated: 1,
                pending: false,
            });
            id
        })
    }

    fn open_pending(&self, subject: &str) -> u64 {
        let id = self.open(subject, None, ROUTE, "users");
        self.with(|registry| registry.streams[usize::try_from(id).unwrap()].pending = true);
        id
    }

    fn decided(&self) -> Vec<u64> {
        let mut ids: Vec<u64> =
            self.with(|registry| registry.decided.iter().map(|(id, _version)| *id).collect());
        ids.sort_unstable();
        ids
    }
}

#[async_trait::async_trait]
impl OpenStreams for Streams {
    fn mark(&self) -> u64 {
        self.with(|registry| u64::try_from(registry.streams.len()).unwrap())
    }

    fn select(&self, scope: &StreamScope) -> Vec<u64> {
        self.with(|registry| {
            registry
                .streams
                .iter()
                .filter(|stream| {
                    scope.everything
                        || scope.subjects.contains(&stream.subject)
                        || stream
                            .session
                            .as_ref()
                            .is_some_and(|session| scope.sessions.contains(session))
                        || scope.routes.iter().any(|id| id.to_string() == stream.route)
                        || scope
                            .services
                            .iter()
                            .any(|service| service.to_string() == stream.service)
                })
                .map(|stream| stream.id)
                .collect()
        })
    }

    async fn reevaluate(&self, stream: u64, version: PolicyVersion) {
        self.with(|registry| {
            registry.decided.push((stream, version.value()));
            let held = &mut registry.streams[usize::try_from(stream).unwrap()];
            held.evaluated = held.evaluated.max(version.value());
            held.pending = false;
        });
    }

    fn settle(&self, mark: u64, version: PolicyVersion) {
        self.with(|registry| {
            for stream in &mut registry.streams {
                if stream.id < mark && !stream.pending {
                    stream.evaluated = stream.evaluated.max(version.value());
                }
            }
        });
    }

    fn lagging(&self, version: PolicyVersion) -> Vec<u64> {
        self.with(|registry| {
            registry
                .streams
                .iter()
                .filter(|stream| stream.evaluated < version.value())
                .map(|stream| stream.id)
                .collect()
        })
    }

    fn finish(&self, version: PolicyVersion, board: &ReevaluationBoard) -> bool {
        let lagging = self.with(|registry| {
            registry
                .streams
                .iter()
                .any(|stream| stream.evaluated < version.value())
        });
        if !lagging {
            board.advance(version);
        }
        !lagging
    }
}

struct Rig {
    streams: Arc<Streams>,
    board: Arc<ReevaluationBoard>,
    reauthorizer: Arc<StreamReauthorizer>,
}

fn rig_over(view: Arc<dyn PolicyView>) -> Rig {
    let streams = Arc::new(Streams::default());
    let board = Arc::new(ReevaluationBoard::new());
    let reauthorizer = Arc::new(StreamReauthorizer::new(
        Arc::<Streams>::clone(&streams),
        view,
        Arc::clone(&board),
    ));
    Rig {
        streams,
        board,
        reauthorizer,
    }
}

fn rig() -> Rig {
    rig_over(Arc::new(FakePolicyView::new()))
}

#[tokio::test]
async fn only_the_streams_of_the_touched_subjects_are_decided_again() {
    let rig = rig();
    for number in 0..1_000_u32 {
        rig.streams
            .open(&user(number).to_string(), None, ROUTE, "users");
    }
    let touched: Vec<String> = (0..10).map(|number| subject_key(number * 100)).collect();

    rig.reauthorizer.reauthorize(change(2, &touched)).await;

    let expected: Vec<u64> = (0..10).map(|number| number * 100).collect();
    assert_eq!(rig.streams.decided(), expected);
}

#[tokio::test]
async fn a_user_cutoff_decides_the_streams_of_the_user_again() {
    let rig = rig();
    rig.streams.open(&user(1).to_string(), None, ROUTE, "users");
    rig.streams.open(&user(2).to_string(), None, ROUTE, "users");

    rig.reauthorizer
        .reauthorize(change(2, &[format!("revocation/user/{}", user(2))]))
        .await;

    assert_eq!(rig.streams.decided(), vec![1]);
}

#[tokio::test]
async fn a_revoked_session_decides_the_streams_of_the_session_again() {
    let rig = rig();
    rig.streams
        .open(&user(1).to_string(), Some("session-1"), ROUTE, "users");
    rig.streams
        .open(&user(1).to_string(), Some("session-2"), ROUTE, "users");

    rig.reauthorizer
        .reauthorize(change(2, &["revocation/session/session-2".to_owned()]))
        .await;

    assert_eq!(rig.streams.decided(), vec![1]);
}

#[tokio::test]
async fn the_holders_of_a_touched_role_come_from_the_reverse_index() {
    let role = RoleId::parse(ROLE).unwrap();
    let snapshot = GatewaySnapshot::at(version(2)).with_role_holders(
        role,
        vec![SubjectRef::user(user(2)), SubjectRef::user(user(3))],
    );
    let rig = rig_over(Arc::new(CountingPolicyView::serving(snapshot)));
    for number in 1..=4 {
        rig.streams
            .open(&user(number).to_string(), None, ROUTE, "users");
    }

    rig.reauthorizer
        .reauthorize(change(2, &[format!("role/{ROLE}")]))
        .await;

    assert_eq!(rig.streams.decided(), vec![1, 2]);
}

#[tokio::test]
async fn a_role_change_without_a_snapshot_decides_every_stream_again() {
    let rig = rig_over(Arc::new(FakePolicyView::failing()));
    rig.streams.open(&user(1).to_string(), None, ROUTE, "users");
    rig.streams.open(&user(2).to_string(), None, ROUTE, "users");

    rig.reauthorizer
        .reauthorize(change(2, &[format!("role/{ROLE}")]))
        .await;

    assert_eq!(rig.streams.decided(), vec![0, 1]);
}

#[tokio::test]
async fn a_global_cutoff_decides_every_stream_again() {
    let rig = rig();
    for number in 0..5 {
        rig.streams
            .open(&user(number).to_string(), None, ROUTE, "users");
    }

    rig.reauthorizer
        .reauthorize(change(2, &["revocation/global".to_owned()]))
        .await;

    assert_eq!(rig.streams.decided(), vec![0, 1, 2, 3, 4]);
}

#[tokio::test]
async fn a_route_change_decides_every_stream_on_the_route_again() {
    let rig = rig();
    rig.streams.open(&user(1).to_string(), None, ROUTE, "users");
    rig.streams.open(
        &user(2).to_string(),
        None,
        "0192f6a0-0000-7000-8000-000000000009",
        "users",
    );
    rig.streams.open(&user(3).to_string(), None, ROUTE, "users");

    rig.reauthorizer
        .reauthorize(change(2, &[format!("route/{ROUTE}")]))
        .await;

    assert_eq!(rig.streams.decided(), vec![0, 2]);
}

#[tokio::test]
async fn a_catalogue_change_decides_the_streams_of_its_service_again() {
    let rig = rig();
    rig.streams.open(&user(1).to_string(), None, ROUTE, "users");
    rig.streams
        .open(&user(2).to_string(), None, ROUTE, "orders");

    rig.reauthorizer
        .reauthorize(change(2, &["catalog/orders/manifest".to_owned()]))
        .await;

    assert_eq!(rig.streams.decided(), vec![1]);
}

#[tokio::test]
async fn an_untouched_stream_is_not_decided_again_but_does_not_hold_the_record_back() {
    let rig = rig();
    rig.streams.open(&user(1).to_string(), None, ROUTE, "users");

    rig.reauthorizer.reauthorize(change(2, &[])).await;

    assert_eq!(rig.streams.decided(), Vec::<u64>::new());
    assert_eq!(rig.board.finished(), 2);
}

#[tokio::test]
async fn a_stream_still_waiting_for_its_first_check_is_decided_before_the_record_moves() {
    let rig = rig();
    rig.streams.open(&user(1).to_string(), None, ROUTE, "users");
    let late = rig.streams.open_pending(&user(2).to_string());

    rig.reauthorizer.reauthorize(change(2, &[])).await;

    assert_eq!(rig.streams.decided(), vec![late]);
    assert_eq!(rig.board.finished(), 2);
}

#[tokio::test]
async fn the_record_starts_at_nothing_and_never_goes_down() {
    let board = ReevaluationBoard::new();
    assert_eq!(board.finished(), -1);

    board.advance(version(5));
    board.advance(version(3));

    assert_eq!(board.finished(), 5);
}

#[tokio::test]
async fn reached_completes_once_the_record_is_at_the_version() {
    let board = Arc::new(ReevaluationBoard::new());
    let waiter = tokio::spawn({
        let board = Arc::clone(&board);
        async move { board.reached(version(4)).await }
    });
    board.advance(version(3));
    tokio::task::yield_now().await;
    assert!(!waiter.is_finished());

    board.advance(version(4));

    tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn changes_that_wait_are_joined_into_one() {
    let board = ReevaluationBoard::new();
    board.submit(change(2, &[subject_key(1)]));
    board.submit(change(5, &[subject_key(2)]));

    let joined = board.next().await;

    assert_eq!(joined.version, version(5));
    assert_eq!(joined.touch.subjects().len(), 2);
}

#[tokio::test]
async fn a_submission_never_waits_for_the_slow_hook() {
    let board = ReevaluationBoard::new();
    for at in 1..=1_000 {
        board.submit(change(at, &[subject_key(1)]));
    }

    assert_eq!(board.next().await.version, version(1_000));
}

#[tokio::test]
async fn the_loop_decides_each_submission_and_stops_on_the_flag() {
    let rig = rig();
    rig.streams.open(&user(1).to_string(), None, ROUTE, "users");
    let (stop, stopping) = watch::channel(false);
    let task = tokio::spawn({
        let reauthorizer = Arc::clone(&rig.reauthorizer);
        async move { reauthorizer.run(stopping).await }
    });

    rig.board.submit(change(2, &[subject_key(1)]));
    tokio::time::timeout(Duration::from_secs(5), rig.board.reached(version(2)))
        .await
        .unwrap();
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(rig.streams.decided(), vec![0]);
}

#[tokio::test]
async fn a_default_board_is_empty() {
    assert_eq!(ReevaluationBoard::default().finished(), -1);
    assert_eq!(StreamReauthorizer::name(), "stream-reauthorizer");
}

/// An open-streams double whose first look for lagging streams is followed by a registration, as
/// when a stream opens while the re-evaluation runs.
#[derive(Debug)]
struct Racing {
    inner: Streams,
    raced: Mutex<bool>,
}

#[async_trait::async_trait]
impl OpenStreams for Racing {
    fn mark(&self) -> u64 {
        self.inner.mark()
    }

    fn select(&self, scope: &StreamScope) -> Vec<u64> {
        self.inner.select(scope)
    }

    async fn reevaluate(&self, stream: u64, version: PolicyVersion) {
        self.inner.reevaluate(stream, version).await;
    }

    fn settle(&self, mark: u64, version: PolicyVersion) {
        self.inner.settle(mark, version);
    }

    fn lagging(&self, version: PolicyVersion) -> Vec<u64> {
        let lagging = self.inner.lagging(version);
        let first = !std::mem::replace(
            &mut *self.raced.lock().unwrap_or_else(PoisonError::into_inner),
            true,
        );
        if first {
            self.inner.open_pending(&user(9).to_string());
        }
        lagging
    }

    fn finish(&self, version: PolicyVersion, board: &ReevaluationBoard) -> bool {
        self.inner.finish(version, board)
    }
}

#[tokio::test]
async fn a_stream_that_registers_during_the_pass_is_decided_before_the_record_moves() {
    let streams = Arc::new(Racing {
        inner: Streams::default(),
        raced: Mutex::new(false),
    });
    let board = Arc::new(ReevaluationBoard::new());
    let reauthorizer = StreamReauthorizer::new(
        Arc::<Racing>::clone(&streams),
        Arc::new(FakePolicyView::new()),
        Arc::clone(&board),
    );

    reauthorizer.reauthorize(change(2, &[])).await;

    assert_eq!(streams.inner.decided().len(), 1);
    assert_eq!(board.finished(), 2);
}
