//! `AdvisoryLockLeadership`, `PgTaskStateRepository` and the migration `create_iam_task_state`:
//! one leader per batch, the lock that ends with the batch transaction, and the recorded runs.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iam_domain::{
    Leadership, RepositoryError, SingletonLeadership as _, SingletonTask, TaskStateRepository as _,
};
use iam_infrastructure::{AdvisoryLockLeadership, PgTaskStateRepository};
use shared_infrastructure::persistence::MIGRATOR;
use sqlx::{PgPool, Row as _};

const TASK: SingletonTask = SingletonTask::new("test-singleton", 7_101);
const OTHER: SingletonTask = SingletonTask::new("other-singleton", 7_102);
const RECORDED_AT: Duration = Duration::from_secs(1_700_000_000);

fn recorded_at() -> SystemTime {
    UNIX_EPOCH.checked_add(RECORDED_AT).unwrap()
}

async fn led(
    leadership: &AdvisoryLockLeadership,
    task: &SingletonTask,
) -> Box<dyn iam_domain::LeaderBatch> {
    match leadership.begin(task).await.unwrap() {
        Leadership::Leader(batch) => batch,
        Leadership::Follower => panic!("the batch must be led"),
    }
}

#[sqlx::test(migrator = "MIGRATOR")]
async fn a_second_batch_of_the_same_task_is_a_follower_while_the_first_is_open(pool: PgPool) {
    let leadership = AdvisoryLockLeadership::new(pool);
    let first = led(&leadership, &TASK).await;

    let second = leadership.begin(&TASK).await.unwrap();

    assert!(matches!(second, Leadership::Follower));
    first.rollback().await.unwrap();
}

#[sqlx::test(migrator = "MIGRATOR")]
async fn the_lock_is_free_again_after_a_commit_and_after_a_rollback(pool: PgPool) {
    let leadership = AdvisoryLockLeadership::new(pool);

    led(&leadership, &TASK).await.commit().await.unwrap();
    led(&leadership, &TASK).await.rollback().await.unwrap();
    let third = leadership.begin(&TASK).await.unwrap();

    assert!(matches!(third, Leadership::Leader(_)));
}

#[sqlx::test(migrator = "MIGRATOR")]
async fn a_dropped_batch_frees_the_lock(pool: PgPool) {
    let leadership = AdvisoryLockLeadership::new(pool);
    drop(led(&leadership, &TASK).await);

    let next = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Leadership::Leader(batch) = leadership.begin(&TASK).await.unwrap() {
                return batch;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;

    assert!(
        next.is_ok(),
        "the lock is released with the dropped transaction"
    );
}

#[sqlx::test(migrator = "MIGRATOR")]
async fn tasks_with_different_constants_lead_at_the_same_time(pool: PgPool) {
    let leadership = AdvisoryLockLeadership::new(pool);
    let first = led(&leadership, &TASK).await;

    let other = leadership.begin(&OTHER).await.unwrap();

    assert!(matches!(other, Leadership::Leader(_)));
    first.rollback().await.unwrap();
}

#[sqlx::test(migrator = "MIGRATOR")]
async fn a_committed_run_is_recorded_and_counted(pool: PgPool) {
    let leadership = AdvisoryLockLeadership::new(pool.clone());
    let states = PgTaskStateRepository::new(pool);
    assert_eq!(states.find(TASK.name()).await.unwrap(), None);

    for _ in 0..2 {
        let mut batch = led(&leadership, &TASK).await;
        batch.record_run(recorded_at()).await.unwrap();
        batch.commit().await.unwrap();
    }
    let state = states.find(TASK.name()).await.unwrap().unwrap();

    assert_eq!(state.run_count, 2);
    assert_eq!(state.last_run_at, recorded_at());
}

#[sqlx::test(migrator = "MIGRATOR")]
async fn a_rolled_back_run_leaves_no_state(pool: PgPool) {
    let leadership = AdvisoryLockLeadership::new(pool.clone());
    let states = PgTaskStateRepository::new(pool);

    let mut batch = led(&leadership, &TASK).await;
    batch.record_run(recorded_at()).await.unwrap();
    batch.rollback().await.unwrap();

    assert_eq!(states.find(TASK.name()).await.unwrap(), None);
}

#[sqlx::test(migrator = "MIGRATOR")]
async fn a_batch_whose_backend_was_terminated_fails_and_leaves_no_state(pool: PgPool) {
    let leadership = AdvisoryLockLeadership::new(pool.clone());
    let states = PgTaskStateRepository::new(pool.clone());
    let mut batch = led(&leadership, &TASK).await;

    let terminated: i64 = sqlx::query(
        "SELECT count(pg_terminate_backend(pid, 5000)) FROM pg_stat_activity \
         WHERE datname = current_database() AND state = 'idle in transaction' AND query LIKE '%pg_try_advisory_xact_lock%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap()
    .get(0);
    let recorded = batch.record_run(recorded_at()).await;
    let next = leadership.begin(&TASK).await.unwrap();

    assert_eq!(terminated, 1);
    assert!(matches!(recorded, Err(RepositoryError::Unavailable(_))));
    assert!(matches!(next, Leadership::Leader(_)));
    assert_eq!(states.find(TASK.name()).await.unwrap(), None);
}

#[sqlx::test(migrator = "MIGRATOR")]
async fn an_unusable_database_is_an_unavailable_repository(pool: PgPool) {
    sqlx::query("DROP TABLE iam_task_state")
        .execute(&pool)
        .await
        .unwrap();
    let states = PgTaskStateRepository::new(pool);

    let error = states.find(TASK.name()).await.unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}

#[sqlx::test(migrator = "MIGRATOR")]
async fn the_task_state_table_refuses_an_empty_name_and_a_zero_count(pool: PgPool) {
    let empty = sqlx::query("INSERT INTO iam_task_state VALUES ('', CURRENT_TIMESTAMP, 1)")
        .execute(&pool)
        .await;
    let zero = sqlx::query("INSERT INTO iam_task_state VALUES ('task', CURRENT_TIMESTAMP, 0)")
        .execute(&pool)
        .await;

    assert!(empty.is_err());
    assert!(zero.is_err());
}

#[sqlx::test(migrations = false)]
async fn the_down_migration_drops_the_table_and_up_creates_it_again(pool: PgPool) {
    MIGRATOR.run(&pool).await.unwrap();
    let version = MIGRATOR
        .iter()
        .find(|migration| migration.description.contains("create iam task state"))
        .unwrap()
        .version;
    let exists = "SELECT to_regclass('iam_task_state') IS NOT NULL";

    MIGRATOR
        .undo(&pool, version.saturating_sub(1))
        .await
        .unwrap();
    let after_down: bool = sqlx::query_scalar(exists).fetch_one(&pool).await.unwrap();
    MIGRATOR.run(&pool).await.unwrap();
    let after_up: bool = sqlx::query_scalar(exists).fetch_one(&pool).await.unwrap();

    assert!(!after_down);
    assert!(after_up);
}
