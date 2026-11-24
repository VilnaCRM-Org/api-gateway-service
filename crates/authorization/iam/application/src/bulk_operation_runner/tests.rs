use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, BulkKind, BulkOperation, BulkOperationId, BulkPacing, BulkStatus, SystemComponent,
};
use test_support::bulk_operation::{
    ChunkBehaviour, FakeBulkOperationRepository, FakeChunkCommitter,
};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::singleton_leadership::FakeSingletonLeadership;
use tokio::time::Instant;

use super::{BulkOperationRunner, BulkRunnerPorts};
use crate::singleton_loop::BatchOutcome;

fn id(number: u32) -> BulkOperationId {
    BulkOperationId::parse(&format!("0190f2a8-7b3c-7d4e-8f10-{number:012x}")).unwrap()
}

fn pending(number: u32, total: u64) -> BulkOperation {
    BulkOperation::pending(
        id(number),
        BulkKind::RoleDeletion,
        total,
        ActorRef::System(SystemComponent::Startup),
        SystemTime::UNIX_EPOCH,
    )
    .unwrap()
}

struct Harness {
    operations: Arc<FakeBulkOperationRepository>,
    committer: Arc<FakeChunkCommitter>,
}

impl Harness {
    fn new(held: &[BulkOperation], behaviour: ChunkBehaviour) -> Self {
        let operations = Arc::new(FakeBulkOperationRepository::holding(held));
        let committer = Arc::new(FakeChunkCommitter::new(
            Arc::clone(&operations),
            behaviour,
            1,
        ));
        Self {
            operations,
            committer,
        }
    }

    async fn batch(&self, records_per_second: u64) -> BatchOperationResult {
        let ports = BulkRunnerPorts {
            operations: Arc::<FakeBulkOperationRepository>::clone(&self.operations),
            committer: Arc::<FakeChunkCommitter>::clone(&self.committer),
            clock: Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
            ids: Arc::new(SequenceUuidGenerator::starting_at(1)),
        };
        let runner = BulkOperationRunner::new(ports, BulkPacing::new(records_per_second).unwrap());
        let singleton = runner.into_loop(
            Arc::new(FakeSingletonLeadership::leading()),
            Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        );
        let started = Instant::now();
        let outcome = singleton.run_batch().await;
        BatchOperationResult {
            outcome,
            elapsed: started.elapsed(),
        }
    }
}

struct BatchOperationResult {
    outcome: BatchOutcome,
    elapsed: Duration,
}

#[test]
fn the_task_is_named_and_has_its_own_lock_constant() {
    assert_eq!(BulkOperationRunner::TASK.name(), "bulk-operation-runner");
    assert_eq!(BulkOperationRunner::TASK.lock_key(), 7_009);
}

#[tokio::test(start_paused = true)]
async fn a_batch_without_operations_commits_without_waiting() {
    let harness = Harness::new(&[], ChunkBehaviour::Commit(1_000));

    let result = harness.batch(2_000).await;

    assert_eq!(result.outcome, BatchOutcome::Committed);
    assert_eq!(result.elapsed, Duration::ZERO);
    assert_eq!(
        harness.committer.commits(),
        Vec::<iam_domain::CommittedChunk>::new()
    );
}

#[tokio::test(start_paused = true)]
async fn ten_thousand_records_at_two_thousand_a_second_take_five_seconds_of_clock_time() {
    let harness = Harness::new(&[pending(1, 10_000)], ChunkBehaviour::Commit(1_000));

    let result = harness.batch(2_000).await;

    assert_eq!(result.outcome, BatchOutcome::Committed);
    assert!(result.elapsed >= Duration::from_secs(5));
    let commits = harness.committer.commits();
    assert_eq!(commits.len(), 10);
    assert!(commits.iter().all(|chunk| chunk.records == 1_000));
    let operation = &harness.operations.snapshot()[0];
    assert_eq!(operation.status, BulkStatus::Completed);
    assert_eq!(operation.applied_records, 10_000);
}

#[tokio::test(start_paused = true)]
async fn a_batch_ends_after_its_share_of_waiting_and_the_next_one_resumes() {
    let harness = Harness::new(&[pending(1, 20_000)], ChunkBehaviour::Commit(1_000));

    let first = harness.batch(2_000).await;
    let after_first = harness.operations.snapshot()[0].applied_records;
    let second = harness.batch(2_000).await;

    assert!(first.elapsed >= Duration::from_secs(5));
    assert!(first.elapsed < Duration::from_secs(6));
    assert_eq!(after_first, 10_000);
    assert_eq!(second.outcome, BatchOutcome::Committed);
    let operation = &harness.operations.snapshot()[0];
    assert_eq!(operation.applied_records, 20_000);
    assert_eq!(harness.committer.commits().len(), 20);
}

#[tokio::test(start_paused = true)]
async fn the_next_operation_runs_after_the_oldest_one_completed() {
    let harness = Harness::new(
        &[pending(2, 500), pending(1, 500)],
        ChunkBehaviour::Commit(1_000),
    );

    harness.batch(2_000).await;

    let stored = harness.operations.snapshot();
    assert_eq!(stored.len(), 2);
    assert!(
        stored
            .iter()
            .all(|parts| parts.status == BulkStatus::Completed)
    );
    assert_eq!(harness.committer.commits().len(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_change_that_cannot_be_applied_fails_the_operation_and_the_batch_goes_on() {
    let harness = Harness::new(
        &[pending(1, 500), pending(2, 500)],
        ChunkBehaviour::Refuse("the plan is gone".to_owned()),
    );

    let result = harness.batch(2_000).await;

    assert_eq!(result.outcome, BatchOutcome::Committed);
    let stored = harness.operations.snapshot();
    assert!(
        stored
            .iter()
            .all(|parts| parts.status == BulkStatus::Failed)
    );
    assert!(stored.iter().all(|parts| {
        parts
            .error
            .as_deref()
            .is_some_and(|error| error.contains("the plan is gone"))
    }));
}

#[tokio::test(start_paused = true)]
async fn an_unavailable_storage_rolls_the_batch_back_and_keeps_the_operation_unfinished() {
    let harness = Harness::new(&[pending(1, 500)], ChunkBehaviour::Unavailable);

    let result = harness.batch(2_000).await;

    assert_eq!(result.outcome, BatchOutcome::RolledBack);
    assert_eq!(harness.operations.snapshot()[0].status, BulkStatus::Pending);
}

#[tokio::test(start_paused = true)]
async fn a_failing_repository_rolls_the_batch_back() {
    let operations = Arc::new(FakeBulkOperationRepository::failing());
    let committer = Arc::new(FakeChunkCommitter::new(
        Arc::clone(&operations),
        ChunkBehaviour::Commit(10),
        1,
    ));
    let harness = Harness {
        operations,
        committer,
    };

    let result = harness.batch(2_000).await;

    assert_eq!(result.outcome, BatchOutcome::RolledBack);
}
