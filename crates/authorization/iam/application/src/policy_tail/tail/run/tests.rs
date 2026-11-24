use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use iam_domain::{FramedRecord, PolicyDigestValue};
use test_support::clock::FixedClock;
use test_support::policy_bootstrap_log::framed_row;
use test_support::policy_tail_log::{FakePolicyTailLog, PollStep, batch, timed};
use tokio::sync::watch;

use super::*;

const ROLE: &str = "role/0192f6a0-0000-7000-8000-000000000001";

fn row(offset: i64) -> FramedRecord {
    framed_row(offset, ROLE, Some("a"), 1, (1, 2, PolicyDigestValue::ZERO))
}

/// An applier that answers from a list and remembers the batches it was given.
#[derive(Debug)]
struct ScriptedApplier {
    answers: Mutex<Vec<ApplyResult>>,
    batches: Mutex<Vec<Vec<FramedRecord>>>,
}

impl ScriptedApplier {
    fn answering(mut answers: Vec<ApplyResult>) -> Self {
        answers.reverse();
        Self {
            answers: Mutex::new(answers),
            batches: Mutex::new(Vec::new()),
        }
    }

    fn batches(&self) -> Vec<Vec<FramedRecord>> {
        self.batches.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl TailApplier for ScriptedApplier {
    async fn apply(&self, records: Vec<FramedRecord>) -> ApplyResult {
        self.batches.lock().unwrap().push(records);
        self.answers
            .lock()
            .unwrap()
            .pop()
            .unwrap_or(ApplyResult::Applied)
    }
}

fn ports(log: &Arc<FakePolicyTailLog>, applier: &Arc<ScriptedApplier>) -> TailPorts {
    TailPorts {
        log: Arc::<FakePolicyTailLog>::clone(log),
        applier: Arc::<ScriptedApplier>::clone(applier),
        clock: Arc::new(FixedClock::at(
            SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(10_000))
                .unwrap(),
        )),
    }
}

async fn run(
    log: &Arc<FakePolicyTailLog>,
    applier: &Arc<ScriptedApplier>,
    machine: TailMachine,
) -> TailEnd {
    let (_stop, stopping) = watch::channel(false);
    run_tail(machine, &ports(log, applier), Duration::ZERO, &stopping).await
}

#[tokio::test]
async fn batches_are_applied_in_order_and_each_poll_starts_after_the_previous_batch() {
    let steps = vec![
        PollStep::Batch(batch(vec![timed(row(3), None)], 0, 4)),
        PollStep::Batch(batch(vec![timed(row(4), None), timed(row(5), None)], 0, 8)),
        PollStep::Batch(batch(Vec::new(), 0, 7)),
    ];
    let log = Arc::new(FakePolicyTailLog::scripted(steps, 6));
    let applier = Arc::new(ScriptedApplier::answering(Vec::new()));

    let end = run(&log, &applier, TailMachine::new(3, 3)).await;

    assert_eq!(
        end,
        TailEnd::Fenced(FenceCause::WatermarkRegression { seen: 8, high: 7 })
    );
    assert_eq!(applier.batches(), vec![vec![row(3)], vec![row(4), row(5)]]);
    assert_eq!(log.positions(), vec![3, 4, 6]);
    assert_eq!(
        log.closes(),
        1,
        "the connection is released when the tail ends"
    );
}

#[tokio::test]
async fn a_fault_the_apply_thread_reports_ends_the_tail() {
    let steps = vec![PollStep::Batch(batch(vec![timed(row(3), None)], 0, 4))];
    let log = Arc::new(FakePolicyTailLog::scripted(steps, 4));
    let applier = Arc::new(ScriptedApplier::answering(vec![ApplyResult::Fenced(
        FenceCause::DigestMismatch { version: 1 },
    )]));

    let end = run(&log, &applier, TailMachine::new(3, 3)).await;

    assert_eq!(
        end,
        TailEnd::Fenced(FenceCause::DigestMismatch { version: 1 })
    );
}

#[tokio::test]
async fn a_dead_apply_thread_ends_the_tail() {
    let steps = vec![PollStep::Batch(batch(vec![timed(row(3), None)], 0, 4))];
    let log = Arc::new(FakePolicyTailLog::scripted(steps, 4));
    let applier = Arc::new(ScriptedApplier::answering(vec![ApplyResult::Gone]));

    let end = run(&log, &applier, TailMachine::new(3, 3)).await;

    assert_eq!(end, TailEnd::ApplierGone);
}

#[tokio::test]
async fn a_dropped_connection_resumes_from_the_position_in_memory() {
    let steps = vec![
        PollStep::Batch(batch(vec![timed(row(3), None)], 0, 4)),
        PollStep::Unavailable,
        PollStep::Batch(batch(vec![timed(row(4), None)], 0, 5)),
        PollStep::Malformed(5),
    ];
    let log = Arc::new(FakePolicyTailLog::scripted(steps, 5));
    let applier = Arc::new(ScriptedApplier::answering(Vec::new()));

    let end = run(&log, &applier, TailMachine::new(3, 3)).await;

    assert_eq!(end, TailEnd::Fenced(FenceCause::Malformed { offset: 5 }));
    assert_eq!(applier.batches(), vec![vec![row(3)], vec![row(4)]]);
    assert_eq!(log.positions(), vec![3, 4, 4, 5]);
}

#[tokio::test]
async fn a_stop_ends_an_idle_tail() {
    let log = Arc::new(FakePolicyTailLog::scripted(Vec::new(), 3));
    let applier = Arc::new(ScriptedApplier::answering(Vec::new()));
    let (stop, stopping) = watch::channel(false);
    let ports = ports(&log, &applier);
    let tail = tokio::spawn(async move {
        run_tail(TailMachine::new(3, 3), &ports, Duration::ZERO, &stopping).await
    });

    tokio::task::yield_now().await;
    stop.send_replace(true);

    assert_eq!(tail.await.unwrap(), TailEnd::Stopped);
}

#[tokio::test]
async fn a_step_that_asks_for_nothing_counts_as_a_failed_poll() {
    let log = Arc::new(FakePolicyTailLog::scripted(Vec::new(), 0));
    let applier = Arc::new(ScriptedApplier::answering(Vec::new()));

    let settled = settle(Vec::new(), &ports(&log, &applier), Duration::ZERO).await;

    assert!(
        matches!(&settled, Settled::Next(TailInput::ReadFailed(reason)) if reason == "the tail made no progress")
    );
    assert_eq!(log.positions(), Vec::<i64>::new());
}
