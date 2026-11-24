//! `PgTokenLifetimeFloor` over the `create_iam_token_lifetime_floor` table: the floor rises with
//! the configured lifetime and never falls.

use std::time::Duration;

use iam_domain::TokenLifetimeFloor as _;
use iam_infrastructure::PgTokenLifetimeFloor;
use sqlx::PgPool;

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_new_database_holds_no_floor(pool: PgPool) {
    assert_eq!(
        PgTokenLifetimeFloor::new(pool).longest().await.unwrap(),
        None
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_floor_rises_to_a_longer_lifetime_and_stays_when_the_lifetime_is_lowered(pool: PgPool) {
    let floor = PgTokenLifetimeFloor::new(pool);

    assert_eq!(
        floor.raise_to(Duration::from_mins(15)).await.unwrap(),
        Duration::from_mins(15)
    );
    assert_eq!(
        floor.raise_to(Duration::from_mins(30)).await.unwrap(),
        Duration::from_mins(30)
    );
    assert_eq!(
        floor.raise_to(Duration::from_mins(15)).await.unwrap(),
        Duration::from_mins(30)
    );
    assert_eq!(
        floor.longest().await.unwrap(),
        Some(Duration::from_mins(30))
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn there_is_one_floor_row_and_it_holds_a_positive_lifetime(pool: PgPool) {
    let floor = PgTokenLifetimeFloor::new(pool.clone());
    floor.raise_to(Duration::from_mins(15)).await.unwrap();

    let second = sqlx::query(
        "INSERT INTO iam_token_lifetime_floor (id, longest_lifetime_seconds) VALUES (2, 900)",
    )
    .execute(&pool)
    .await;
    let zero = sqlx::query(
        "UPDATE iam_token_lifetime_floor SET longest_lifetime_seconds = 0 WHERE id = 1",
    )
    .execute(&pool)
    .await;

    assert!(second.is_err());
    assert!(zero.is_err());
}
