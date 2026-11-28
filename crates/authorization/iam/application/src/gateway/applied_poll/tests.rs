use std::sync::Arc;
use std::time::Duration;

use iam_domain::PolicyVersion;

use super::{
    AppliedAnswer, AppliedPoll, AppliedPollSettings, BootstrapHighWater, PolicyVersionBoard,
    ReevaluationBoard,
};

const HARD_BOUND: Duration = Duration::from_secs(15);

fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

struct Pod {
    poll: Arc<AppliedPoll>,
    versions: Arc<PolicyVersionBoard>,
    reevaluation: Arc<ReevaluationBoard>,
    high_water: Arc<BootstrapHighWater>,
}

impl Pod {
    fn with(max_concurrent: usize) -> Self {
        let versions = Arc::new(PolicyVersionBoard::new());
        let reevaluation = Arc::new(ReevaluationBoard::new());
        let high_water = Arc::new(BootstrapHighWater::new());
        let poll = Arc::new(AppliedPoll::new(
            Arc::clone(&versions),
            Arc::clone(&reevaluation),
            Arc::clone(&high_water),
            AppliedPollSettings {
                pod: "gateway-0".to_owned(),
                hard_bound: HARD_BOUND,
                max_concurrent,
            },
        ));
        Self {
            poll,
            versions,
            reevaluation,
            high_water,
        }
    }

    fn new() -> Self {
        Self::with(256)
    }

    /// Publishes `at` and finishes the re-evaluation of its streams.
    fn apply(&self, at: i64) {
        self.publish(at);
        self.reevaluation.advance(version(at));
    }

    fn publish(&self, at: i64) {
        self.versions.note_published(Some(version(at)));
    }

    fn ask(&self, at: i64, offset: i64, wait: Duration) -> tokio::task::JoinHandle<AppliedAnswer> {
        let poll = Arc::clone(&self.poll);
        tokio::spawn(async move { poll.poll(version(at), offset, wait).await })
    }
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(1)).await;
}

#[tokio::test(start_paused = true)]
async fn a_pod_that_enforces_the_version_answers_at_once_with_what_it_published() {
    let pod = Pod::new();
    pod.apply(5);

    let answer = pod.poll.poll(version(4), 0, Duration::from_secs(5)).await;

    assert_eq!(
        answer,
        AppliedAnswer::Applied {
            published: Some(version(5))
        }
    );
}

#[tokio::test(start_paused = true)]
async fn a_poll_waits_for_the_publication_and_its_stream_re_evaluation() {
    let pod = Pod::new();
    pod.apply(4);
    let waiting = pod.ask(5, 99, Duration::from_secs(10));
    settle().await;
    assert!(!waiting.is_finished());

    pod.publish(5);
    settle().await;
    assert!(!waiting.is_finished(), "the streams are still undecided");

    pod.reevaluation.advance(version(5));

    assert_eq!(
        waiting.await.unwrap(),
        AppliedAnswer::Applied {
            published: Some(version(5))
        }
    );
}

#[tokio::test(start_paused = true)]
async fn a_slow_re_evaluation_keeps_the_poll_waiting_after_the_publication() {
    let pod = Pod::new();
    let waiting = pod.ask(1, 99, Duration::from_secs(10));
    pod.publish(1);
    tokio::time::sleep(Duration::from_secs(9)).await;
    assert!(!waiting.is_finished());

    pod.reevaluation.advance(version(1));

    assert!(matches!(
        waiting.await.unwrap(),
        AppliedAnswer::Applied { .. }
    ));
}

#[tokio::test(start_paused = true)]
async fn a_bootstrapping_pod_answers_at_once_when_hw0_lies_beyond_the_offset() {
    let pod = Pod::new();
    pod.high_water.capture(10);

    let answer = pod.poll.poll(version(3), 9, Duration::from_secs(5)).await;

    assert_eq!(answer, AppliedAnswer::Applied { published: None });
}

#[tokio::test(start_paused = true)]
async fn a_bootstrapping_pod_waits_when_hw0_lies_at_or_below_the_offset() {
    let pod = Pod::new();
    pod.high_water.capture(10);
    let waiting = pod.ask(3, 10, Duration::from_secs(5));
    settle().await;
    assert!(!waiting.is_finished());

    assert_eq!(waiting.await.unwrap(), AppliedAnswer::Unanswered);
}

#[tokio::test(start_paused = true)]
async fn a_waiting_poll_answers_when_the_bootstrap_captures_hw0_beyond_its_offset() {
    let pod = Pod::new();
    let waiting = pod.ask(3, 4, Duration::from_secs(5));
    settle().await;
    assert!(!waiting.is_finished());

    pod.high_water.capture(5);

    assert_eq!(
        waiting.await.unwrap(),
        AppliedAnswer::Applied { published: None }
    );
}

#[tokio::test(start_paused = true)]
async fn a_fenced_pod_on_an_older_snapshot_answers_without_an_acknowledgement() {
    let pod = Pod::new();
    pod.apply(4);

    let started = tokio::time::Instant::now();
    let answer = pod.poll.poll(version(5), 99, Duration::from_secs(3)).await;

    assert_eq!(answer, AppliedAnswer::Unanswered);
    assert_eq!(started.elapsed(), Duration::from_secs(3));
}

#[tokio::test(start_paused = true)]
async fn the_wait_is_capped_at_the_hard_bound_plus_one_second() {
    let pod = Pod::new();

    let started = tokio::time::Instant::now();
    let answer = pod.poll.poll(version(1), 99, Duration::from_hours(1)).await;

    assert_eq!(answer, AppliedAnswer::Unanswered);
    assert_eq!(started.elapsed(), HARD_BOUND + Duration::from_secs(1));
}

#[tokio::test(start_paused = true)]
async fn each_of_many_polls_answers_when_its_own_version_is_applied() {
    let pod = Pod::new();
    let polls: Vec<_> = (1..=100)
        .map(|at| (at, pod.ask(at, 999, Duration::from_secs(10))))
        .collect();
    settle().await;
    assert!(polls.iter().all(|(_, poll)| !poll.is_finished()));

    for applied in 1..=100 {
        pod.apply(applied);
        settle().await;
        for (at, poll) in &polls {
            assert_eq!(poll.is_finished(), *at <= applied, "poll {at} at {applied}");
        }
    }
    for (_, poll) in polls {
        assert!(matches!(poll.await.unwrap(), AppliedAnswer::Applied { .. }));
    }
}

#[tokio::test(start_paused = true)]
async fn polls_at_the_limit_hold_their_slots_and_one_more_is_busy_at_once() {
    let pod = Pod::with(2);
    let first = pod.ask(9, 99, Duration::from_secs(10));
    let second = pod.ask(9, 99, Duration::from_secs(10));
    settle().await;

    let started = tokio::time::Instant::now();
    let third = pod.poll.poll(version(9), 99, Duration::from_secs(10)).await;

    assert_eq!(third, AppliedAnswer::Busy);
    assert_eq!(started.elapsed(), Duration::ZERO);
    pod.apply(9);
    assert!(matches!(
        first.await.unwrap(),
        AppliedAnswer::Applied { .. }
    ));
    assert!(matches!(
        second.await.unwrap(),
        AppliedAnswer::Applied { .. }
    ));
    assert!(matches!(
        pod.poll.poll(version(9), 99, Duration::ZERO).await,
        AppliedAnswer::Applied { .. }
    ));
}

#[tokio::test(start_paused = true)]
async fn a_finished_poll_frees_its_slot() {
    let pod = Pod::with(1);
    assert_eq!(
        pod.poll.poll(version(9), 99, Duration::from_secs(1)).await,
        AppliedAnswer::Unanswered
    );

    assert_eq!(
        pod.poll.poll(version(9), 99, Duration::from_secs(1)).await,
        AppliedAnswer::Unanswered
    );
}

#[test]
fn the_poll_reports_the_pod_and_its_hard_bound() {
    let pod = Pod::new();

    assert_eq!(pod.poll.pod(), "gateway-0");
    assert_eq!(pod.poll.hard_bound(), HARD_BOUND);
}
