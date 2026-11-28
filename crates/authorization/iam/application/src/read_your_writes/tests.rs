use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use iam_domain::{PolicySnapshot, PolicyVersion, PolicyView};
use test_support::policy_view::EmptySnapshot;

use super::{BarrierVerdict, PolicyVersionBoard, ReadYourWritesBarrier};

const WAIT: Duration = Duration::from_secs(1);

fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

/// A view whose published version a test moves.
#[derive(Debug, Default)]
struct MovingView {
    held: Mutex<Option<PolicyVersion>>,
}

impl MovingView {
    fn publish(&self, version: PolicyVersion) {
        *self.held.lock().unwrap_or_else(PoisonError::into_inner) = Some(version);
    }
}

impl PolicyView for MovingView {
    fn current(&self) -> Option<Arc<dyn PolicySnapshot>> {
        let held = *self.held.lock().unwrap_or_else(PoisonError::into_inner);
        held.map(|held| -> Arc<dyn PolicySnapshot> { Arc::new(EmptySnapshot::at(held)) })
    }
}

fn barrier() -> (
    Arc<ReadYourWritesBarrier>,
    Arc<MovingView>,
    Arc<PolicyVersionBoard>,
) {
    let view = Arc::new(MovingView::default());
    let board = Arc::new(PolicyVersionBoard::new());
    let barrier = Arc::new(ReadYourWritesBarrier::new(
        Arc::<MovingView>::clone(&view),
        Arc::clone(&board),
        WAIT,
    ));
    (barrier, view, board)
}

#[test]
fn a_new_board_has_seen_nothing() {
    assert_eq!(PolicyVersionBoard::new().highest_seen(), None);
    assert_eq!(PolicyVersionBoard::default().highest_seen(), None);
}

#[test]
fn the_highest_version_seen_never_goes_down() {
    let board = PolicyVersionBoard::new();

    board.note_seen(version(7));
    board.note_seen(version(3));

    assert_eq!(board.highest_seen(), Some(version(7)));
}

#[test]
fn a_published_version_counts_as_seen_and_withdrawing_it_forgets_nothing() {
    let board = PolicyVersionBoard::new();

    board.note_published(Some(version(4)));
    board.note_published(None);

    assert_eq!(board.highest_seen(), Some(version(4)));
}

#[tokio::test]
async fn a_version_above_the_highest_seen_is_refused_at_once() {
    let (barrier, view, board) = barrier();
    view.publish(version(5));
    board.note_published(Some(version(5)));

    assert_eq!(barrier.admit(version(6)).await, BarrierVerdict::Propagating);
}

#[tokio::test]
async fn a_version_the_snapshot_holds_goes_through_without_waiting() {
    let (barrier, view, board) = barrier();
    view.publish(version(5));
    board.note_published(Some(version(5)));

    assert_eq!(barrier.admit(version(5)).await, BarrierVerdict::Proceed);
    assert_eq!(barrier.admit(version(2)).await, BarrierVerdict::Proceed);
}

#[tokio::test(start_paused = true)]
async fn a_seen_version_waits_for_its_snapshot_and_goes_on_when_it_is_published() {
    let (barrier, view, board) = barrier();
    view.publish(version(5));
    board.note_published(Some(version(5)));
    board.note_seen(version(6));
    let waiting = tokio::spawn({
        let barrier = Arc::clone(&barrier);
        async move { barrier.admit(version(6)).await }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!waiting.is_finished());

    view.publish(version(6));
    board.note_published(Some(version(6)));

    assert_eq!(waiting.await.unwrap(), BarrierVerdict::Proceed);
}

#[tokio::test(start_paused = true)]
async fn a_seen_version_that_is_not_published_in_time_is_refused() {
    let (barrier, view, board) = barrier();
    view.publish(version(5));
    board.note_published(Some(version(5)));
    board.note_seen(version(6));

    let verdict = barrier.admit(version(6)).await;

    assert_eq!(verdict, BarrierVerdict::Propagating);
}

#[tokio::test(start_paused = true)]
async fn a_pod_without_a_snapshot_refuses_after_the_wait() {
    let (barrier, _view, board) = barrier();
    board.note_seen(version(1));

    assert_eq!(barrier.admit(version(1)).await, BarrierVerdict::Propagating);
}

#[test]
fn the_published_version_is_none_until_a_snapshot_is_published_and_again_when_it_is_withdrawn() {
    let board = PolicyVersionBoard::new();
    assert_eq!(board.published(), None);

    board.note_published(Some(version(3)));
    assert_eq!(board.published(), Some(version(3)));

    board.note_published(None);
    assert_eq!(board.published(), None);
}
