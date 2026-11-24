use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{DecisionEffect, IamUnitOfWork as _, PropagationOutcome, WriteMode};
use test_support::clock::ManualClock;
use test_support::propagation_store::FakePropagationStore;
use test_support::seed::TestRng;
use test_support::unit_of_work::{FakeIamUnitOfWork, iam_change};

use super::PublishingUnitOfWork;

const TIMEOUT: Duration = Duration::from_secs(5);

fn unit(
    inner: FakeIamUnitOfWork,
    store: &Arc<FakePropagationStore>,
    clock: &Arc<ManualClock>,
) -> PublishingUnitOfWork {
    PublishingUnitOfWork::new(
        Arc::new(inner),
        Arc::<FakePropagationStore>::clone(store),
        Arc::<ManualClock>::clone(clock),
        TIMEOUT,
    )
}

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::at(
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(1_000))
            .unwrap(),
    ))
}

#[tokio::test(start_paused = true)]
async fn a_published_version_returns_its_offset_and_stores_the_outcome() {
    let store = Arc::new(FakePropagationStore::publishing(1, 42));
    let unit = unit(FakeIamUnitOfWork::new(), &store, &clock());
    let change = iam_change(&mut TestRng::from_seed(1), DecisionEffect::Affected, 0);

    let receipt = unit.commit(change, WriteMode::Published).await.unwrap();

    assert_eq!(
        receipt.propagation(),
        Some(PropagationOutcome::Published { offset: 42 })
    );
    assert_eq!(
        store.recorded(),
        vec![(
            receipt.change_id(),
            PropagationOutcome::Published { offset: 42 }
        )]
    );
}

#[tokio::test(start_paused = true)]
async fn a_version_that_is_not_acknowledged_in_time_is_committed_pending() {
    let store = Arc::new(FakePropagationStore::new());
    let clock = clock();
    let unit = PublishingUnitOfWork::new(
        Arc::new(FakeIamUnitOfWork::new()),
        Arc::<FakePropagationStore>::clone(&store),
        Arc::<ManualClock>::clone(&clock),
        Duration::ZERO,
    );
    let change = iam_change(&mut TestRng::from_seed(2), DecisionEffect::Affected, 0);

    let receipt = unit.commit(change, WriteMode::Published).await.unwrap();

    assert_eq!(
        receipt.propagation(),
        Some(PropagationOutcome::CommittedPending)
    );
    assert_eq!(
        store.recorded(),
        vec![(receipt.change_id(), PropagationOutcome::CommittedPending)]
    );
}

#[tokio::test(start_paused = true)]
async fn the_wait_ends_when_the_clock_passes_the_timeout() {
    let store = Arc::new(FakePropagationStore::new());
    let clock = clock();
    let unit = unit(FakeIamUnitOfWork::new(), &store, &clock);
    let change = iam_change(&mut TestRng::from_seed(3), DecisionEffect::Affected, 0);
    let mover = Arc::clone(&clock);
    let advance = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        mover.advance(TIMEOUT);
    });

    let receipt = unit.commit(change, WriteMode::Published).await.unwrap();
    advance.await.unwrap();

    assert_eq!(
        receipt.propagation(),
        Some(PropagationOutcome::CommittedPending)
    );
    assert!(store.polls() > 1);
}

#[tokio::test(start_paused = true)]
async fn a_change_that_does_not_affect_decisions_waits_for_nothing() {
    let store = Arc::new(FakePropagationStore::new());
    let unit = unit(FakeIamUnitOfWork::new(), &store, &clock());
    let change = iam_change(&mut TestRng::from_seed(4), DecisionEffect::Unaffected, 0);

    let receipt = unit.commit(change, WriteMode::Published).await.unwrap();

    assert_eq!(receipt.propagation(), None);
    assert_eq!(store.polls(), 0);
    assert_eq!(store.recorded().len(), 0);
}

#[tokio::test(start_paused = true)]
async fn an_unreadable_offset_leaves_the_version_unconfirmed() {
    let store = Arc::new(FakePropagationStore::failing());
    let unit = unit(FakeIamUnitOfWork::new(), &store, &clock());
    let change = iam_change(&mut TestRng::from_seed(5), DecisionEffect::Affected, 0);

    let receipt = unit.commit(change, WriteMode::Published).await.unwrap();

    assert_eq!(
        receipt.propagation(),
        Some(PropagationOutcome::CommittedPending)
    );
}

#[tokio::test(start_paused = true)]
async fn a_refused_commit_waits_for_nothing() {
    let store = Arc::new(FakePropagationStore::new());
    let unit = unit(FakeIamUnitOfWork::failing(), &store, &clock());
    let change = iam_change(&mut TestRng::from_seed(6), DecisionEffect::Affected, 0);

    let error = unit.commit(change, WriteMode::Published).await.unwrap_err();

    assert!(matches!(error, iam_domain::RepositoryError::Unavailable(_)));
    assert_eq!(store.polls(), 0);
}
