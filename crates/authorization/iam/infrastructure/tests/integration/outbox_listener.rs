//! `PgOutboxListener` and the wake-up of `PgIamUnitOfWork`: a committed change notifies the
//! channel `iam_outbox`, and a rolled-back one does not.

use std::time::Duration;

use iam_domain::{DecisionEffect, IamUnitOfWork as _};
use iam_infrastructure::{PgIamUnitOfWork, PgOutboxListener};
use sqlx::PgPool;
use test_support::seed::TestRng;
use test_support::unit_of_work::iam_change;

/// How long a test waits for a notification that must arrive.
const DEADLINE: Duration = Duration::from_secs(10);

/// How long a test waits for a notification that must not arrive.
const QUIET: Duration = Duration::from_millis(500);

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_notification_of_the_channel_wakes_the_listener(pool: PgPool) {
    let mut listener = PgOutboxListener::connect(&pool).await.unwrap();

    sqlx::query("SELECT pg_notify('iam_outbox', '')")
        .execute(&pool)
        .await
        .unwrap();

    tokio::time::timeout(DEADLINE, listener.notified())
        .await
        .unwrap()
        .unwrap();
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_committed_change_notifies_the_listener(pool: PgPool) {
    let mut listener = PgOutboxListener::connect(&pool).await.unwrap();
    let mut rng = TestRng::from_env();

    PgIamUnitOfWork::new(pool)
        .commit(
            iam_change(&mut rng, DecisionEffect::Affected, 1),
            iam_domain::WriteMode::Published,
        )
        .await
        .unwrap();

    tokio::time::timeout(DEADLINE, listener.notified())
        .await
        .unwrap()
        .unwrap();
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_rolled_back_transaction_does_not_notify_the_listener(pool: PgPool) {
    let mut listener = PgOutboxListener::connect(&pool).await.unwrap();
    let mut transaction = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_notify('iam_outbox', '')")
        .execute(&mut *transaction)
        .await
        .unwrap();
    transaction.rollback().await.unwrap();

    let heard = tokio::time::timeout(QUIET, listener.notified()).await;

    assert!(heard.is_err());
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_pool_that_cannot_connect_is_an_unavailable_listener(pool: PgPool) {
    pool.close().await;

    let listener = PgOutboxListener::connect(&pool).await;

    assert!(listener.is_err());
}
