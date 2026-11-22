use std::time::Duration;

use iam_domain::{PolicyEpoch, PolicyEpochRepository as _, RepositoryError};
use iam_infrastructure::PgPolicyEpochRepository;
use shared_infrastructure::persistence::{PostgresSettings, connect_lazy};
use sqlx::PgPool;
use test_support::policy_epoch::{policy_epoch, seeded_policy_epoch};
use test_support::seed::TestRng;
use tokio::time::Instant;

/// URL that nothing listens on: the "unreachable database" case. No container is stopped.
const DEAD_DATABASE_URL: &str = "postgres://app:unused@127.0.0.1:1/app";

/// Overwrites the single row with `epoch`.
async fn store(pool: &PgPool, epoch: &PolicyEpoch) {
    let updated = sqlx::query(
        "UPDATE iam_policy_epoch SET version = $1, digest = $2, log_epoch = $3, relay_epoch = $4, \
         catalog_epoch = $5 WHERE id = 1",
    )
    .bind(epoch.version().value())
    .bind(epoch.digest().as_bytes().as_slice())
    .bind(epoch.log_epoch().value())
    .bind(epoch.relay_epoch().value())
    .bind(epoch.catalog_epoch())
    .execute(pool)
    .await
    .unwrap();
    assert_eq!(updated.rows_affected(), 1);
}

async fn execute(pool: &PgPool, sql: &'static str) {
    sqlx::query(sql).execute(pool).await.unwrap();
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_migrated_database_holds_the_seeded_epoch(pool: PgPool) {
    let repository = PgPolicyEpochRepository::new(pool);

    let current = repository.current().await.unwrap();

    assert_eq!(current, seeded_policy_epoch());
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_stored_epoch_is_read_with_every_column(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let epoch = policy_epoch(&mut rng);
    store(&pool, &epoch).await;
    let repository = PgPolicyEpochRepository::new(pool);

    let current = repository.current().await.unwrap();

    assert_eq!(current, epoch);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_missing_row_is_not_found(pool: PgPool) {
    execute(&pool, "DELETE FROM iam_policy_epoch").await;
    let repository = PgPolicyEpochRepository::new(pool);

    let error = repository.current().await.unwrap_err();

    assert!(matches!(error, RepositoryError::NotFound));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_stored_digest_that_is_not_16_bytes_is_unavailable(pool: PgPool) {
    execute(
        &pool,
        "ALTER TABLE iam_policy_epoch DROP CONSTRAINT iam_policy_epoch_digest_check",
    )
    .await;
    execute(
        &pool,
        "UPDATE iam_policy_epoch SET digest = decode('00ff', 'hex')",
    )
    .await;
    let repository = PgPolicyEpochRepository::new(pool);

    let error = repository.current().await.unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_stored_negative_version_is_unavailable(pool: PgPool) {
    execute(
        &pool,
        "ALTER TABLE iam_policy_epoch DROP CONSTRAINT iam_policy_epoch_version_check",
    )
    .await;
    execute(&pool, "UPDATE iam_policy_epoch SET version = -1").await;
    let repository = PgPolicyEpochRepository::new(pool);

    let error = repository.current().await.unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}

#[tokio::test]
async fn an_unreachable_database_is_unavailable_within_the_acquire_timeout() {
    let acquire_timeout = Duration::from_millis(500);
    let pool = connect_lazy(&PostgresSettings {
        url: DEAD_DATABASE_URL.to_owned(),
        max_connections: 1,
        acquire_timeout,
        statement_timeout: Duration::from_secs(1),
    })
    .unwrap();
    let repository = PgPolicyEpochRepository::new(pool);
    let bound = acquire_timeout + Duration::from_secs(1);

    let started = Instant::now();
    let error = repository.current().await.unwrap_err();
    let elapsed = started.elapsed();

    assert!(elapsed < bound, "{elapsed:?}");
    assert!(matches!(error, RepositoryError::Unavailable(_)));
    let text = format!("{error} {error:?}").to_lowercase();
    assert_eq!(error.to_string(), "the repository is unavailable");
    assert!(!text.contains("select"));
}
