//! `PgStartupLock`: a named lock that one holder at a time owns and that ends with its guard.

use std::time::Duration;

use iam_domain::{OWN_SPECIFICATIONS_LOCK, StartupLock as _};
use iam_infrastructure::PgStartupLock;
use sqlx::PgPool;

/// Time that a second holder gets to prove that it is still waiting.
const WAIT: Duration = Duration::from_millis(300);

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_second_holder_of_the_same_name_waits_until_the_guard_is_dropped(pool: PgPool) {
    let lock = PgStartupLock::new(pool);
    let first = lock.acquire(OWN_SPECIFICATIONS_LOCK).await.unwrap();

    let blocked = tokio::time::timeout(WAIT, lock.acquire(OWN_SPECIFICATIONS_LOCK)).await;
    assert!(blocked.is_err(), "the lock must still be held");

    drop(first);
    let second = tokio::time::timeout(
        Duration::from_secs(10),
        lock.acquire(OWN_SPECIFICATIONS_LOCK),
    )
    .await
    .expect("the lock is released with the guard");
    assert!(second.is_ok());
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn locks_of_different_names_do_not_wait_for_each_other(pool: PgPool) {
    let lock = PgStartupLock::new(pool);
    let first = lock.acquire("first").await.unwrap();

    let second = tokio::time::timeout(Duration::from_secs(10), lock.acquire("second"))
        .await
        .expect("another name is free");

    assert!(second.is_ok());
    drop(first);
}
