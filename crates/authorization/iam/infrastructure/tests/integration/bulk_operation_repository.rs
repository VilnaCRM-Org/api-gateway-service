//! `PgBulkOperationRepository`: the stored progress of a bulk operation, its listing in creation
//! order and the oldest unfinished operation that a restarted runner resumes.

use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, BulkKind, BulkOperation, BulkOperationId, BulkOperationRepository as _, BulkStamp,
    BulkStatus, PolicyVersion, RepositoryError, SystemComponent,
};
use iam_infrastructure::PgBulkOperationRepository;
use shared_domain::Uuid;
use sqlx::PgPool;

fn id(number: u32) -> BulkOperationId {
    BulkOperationId::parse(&format!("0190f2a8-7b3c-7d4e-8f10-{number:012x}")).unwrap()
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(1_700_000_000))
        .and_then(|base| base.checked_add(Duration::from_secs(seconds)))
        .unwrap()
}

fn pending(number: u32, total: u64) -> BulkOperation {
    BulkOperation::pending(
        id(number),
        BulkKind::RoleDeletion,
        total,
        ActorRef::System(SystemComponent::Startup),
        at(0),
    )
    .unwrap()
}

fn stamp(seconds: u64) -> BulkStamp {
    BulkStamp {
        event_id: Uuid::parse("01890a5d-ac96-774b-bcce-b302099a8057").unwrap(),
        occurred_at: at(seconds),
    }
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_stored_operation_is_read_back_and_its_progress_saved(pool: PgPool) {
    let repository = PgBulkOperationRepository::new(pool);
    let mut operation = pending(1, 2_500);
    repository.insert(&operation).await.unwrap();

    operation
        .record_chunk(1_000, PolicyVersion::new(5).unwrap(), stamp(1))
        .unwrap();
    repository.save(&operation).await.unwrap();

    let stored = repository.find(id(1)).await.unwrap().unwrap();
    assert_eq!(stored.parts(), operation.parts());
    assert_eq!(stored.parts().status, BulkStatus::Running);
    assert_eq!(repository.find(id(2)).await.unwrap().map(|_op| ()), None);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_known_id_is_not_inserted_twice_and_an_unknown_one_is_not_saved(pool: PgPool) {
    let repository = PgBulkOperationRepository::new(pool);
    repository.insert(&pending(1, 10)).await.unwrap();

    let again = repository.insert(&pending(1, 10)).await.unwrap_err();
    let unknown = repository.save(&pending(2, 10)).await.unwrap_err();

    assert!(matches!(again, RepositoryError::AlreadyExists));
    assert!(matches!(unknown, RepositoryError::NotFound));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn operations_are_listed_in_creation_order_after_a_cursor(pool: PgPool) {
    let repository = PgBulkOperationRepository::new(pool);
    for number in [3, 1, 2] {
        repository.insert(&pending(number, 10)).await.unwrap();
    }

    let first = repository.list(None, 2).await.unwrap();
    let rest = repository.list(Some(id(2)), 10).await.unwrap();

    let ids = |page: &[BulkOperation]| page.iter().map(|op| op.parts().id).collect::<Vec<_>>();
    assert_eq!(ids(&first), vec![id(1), id(2)]);
    assert_eq!(ids(&rest), vec![id(3)]);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_oldest_unfinished_operation_skips_finished_ones(pool: PgPool) {
    let repository = PgBulkOperationRepository::new(pool);
    assert!(repository.oldest_unfinished().await.unwrap().is_none());
    let mut done = pending(1, 1);
    repository.insert(&done).await.unwrap();
    done.record_chunk(1, PolicyVersion::new(1).unwrap(), stamp(1))
        .unwrap();
    repository.save(&done).await.unwrap();
    repository.insert(&pending(2, 10)).await.unwrap();
    repository.insert(&pending(3, 10)).await.unwrap();

    let oldest = repository.oldest_unfinished().await.unwrap().unwrap();

    assert_eq!(oldest.parts().id, id(2));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_role_target_is_stored_once_and_read_back(pool: PgPool) {
    use iam_domain::{BulkRoleTargetStore as _, RoleId};
    use iam_infrastructure::PgBulkRoleTargetStore;

    let store = PgBulkRoleTargetStore::new(pool);
    let role = RoleId::parse("7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b").unwrap();

    assert!(store.find(id(1)).await.unwrap().is_none());
    store.insert(id(1), role).await.unwrap();
    let again = store.insert(id(1), role).await.unwrap_err();

    assert_eq!(store.find(id(1)).await.unwrap(), Some(role));
    assert!(matches!(again, RepositoryError::AlreadyExists));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_chunk_change_saves_the_progress_only_over_the_expected_applied_records(pool: PgPool) {
    use iam_domain::{
        BulkProgressStatement, ChangeStatement, DecisionEffect, IamUnitOfWork as _, WriteMode,
    };
    use iam_infrastructure::PgIamUnitOfWork;
    use test_support::seed::TestRng;
    use test_support::unit_of_work::{iam_change, rebuilt};

    let repository = PgBulkOperationRepository::new(pool.clone());
    let unit = PgIamUnitOfWork::new(pool);
    let mut operation = pending(1, 2_500);
    repository.insert(&operation).await.unwrap();
    operation
        .record_chunk(1_000, PolicyVersion::new(1).unwrap(), stamp(1))
        .unwrap();
    let progress = BulkProgressStatement::after_chunk(&operation, 0);
    let mut rng = TestRng::from_env();
    let chunk = |rng: &mut TestRng| {
        rebuilt(&iam_change(rng, DecisionEffect::Affected, 0), |parts| {
            parts.statements = vec![ChangeStatement::SaveBulkProgress(Box::new(
                progress.clone(),
            ))];
        })
    };

    unit.commit(chunk(&mut rng), WriteMode::Published)
        .await
        .unwrap();
    let replayed = unit
        .commit(chunk(&mut rng), WriteMode::Published)
        .await
        .unwrap_err();

    let stored = repository.find(id(1)).await.unwrap().unwrap();
    assert_eq!(stored.parts(), operation.parts());
    assert!(
        matches!(replayed, RepositoryError::Conflict),
        "{replayed:?}"
    );
}
