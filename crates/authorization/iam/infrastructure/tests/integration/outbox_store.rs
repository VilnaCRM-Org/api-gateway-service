//! `PgOutboxStore`: the claim of the unpublished rows in order, the takeover of the relay with the
//! latest state of every key, the marks fenced by the relay epoch and the cleanup of old rows.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iam_domain::{OutboxKind, OutboxStore as _, PublishedRow, RelayEpoch, RepositoryError};
use iam_infrastructure::PgOutboxStore;
use shared_domain::Uuid;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;
use sqlx::{PgPool, Row as _};

const NOW: u64 = 1_700_000_000;

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

/// A row id that is unique within the test.
fn id(number: u128) -> SqlUuid {
    SqlUuid::from_u128(
        0x0190_f2a8_7b3c_7d4e_8f10_0000_0000_0000_u128
            .checked_add(number)
            .unwrap(),
    )
}

/// Inserts a state row of `key` in `version` at position `seq` of `count`.
async fn state_row(pool: &PgPool, number: u128, key: &str, version: i64, seq: i32) {
    sqlx::query(
        "INSERT INTO iam_outbox (id, kind, topic, record_key, payload, policy_version, seq, count,
            digest_after, log_epoch, occurred_at)
        VALUES ($1, 'state', 'iam.policy.state.v1', $2, $3, $4, $5, 9, decode(repeat('00', 16), 'hex'),
            0, now())",
    )
    .bind(id(number))
    .bind(key)
    .bind(if key == "role/gone" { None } else { Some("{}") })
    .bind(version)
    .bind(seq)
    .execute(pool)
    .await
    .unwrap();
}

/// Inserts an event row of `version`.
async fn event_row(pool: &PgPool, number: u128, version: i64) {
    sqlx::query(
        "INSERT INTO iam_outbox (id, kind, topic, record_key, payload, policy_version, log_epoch,
            event_type, aggregate_id, occurred_at)
        VALUES ($1, 'event', 'iam.events.v1', 'aggregate', '{}', $2, 0, 'iam.role.created',
            'aggregate', now())",
    )
    .bind(id(number))
    .bind(version)
    .execute(pool)
    .await
    .unwrap();
}

async fn published_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM iam_outbox WHERE published_at IS NOT NULL")
        .fetch_one(pool)
        .await
        .unwrap()
}

fn published(number: u128, offset: i64) -> PublishedRow {
    PublishedRow {
        id: Uuid::from_uuid(id(number)),
        offset,
    }
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn unpublished_rows_come_in_version_and_sequence_order_with_events_after_their_state(
    pool: PgPool,
) {
    event_row(&pool, 1, 2).await;
    state_row(&pool, 2, "role/b", 2, 2).await;
    state_row(&pool, 3, "role/a", 2, 1).await;
    state_row(&pool, 4, "role/c", 1, 1).await;
    let store = PgOutboxStore::new(pool);

    let claimed = store.claim_unpublished(10).await.unwrap();

    let keys: Vec<_> = claimed.iter().map(|row| row.record_key.as_str()).collect();
    assert_eq!(keys, ["role/c", "role/a", "role/b", "aggregate"]);
    assert_eq!(claimed[1].kind, OutboxKind::State);
    assert_eq!(claimed[1].seq, Some(1));
    assert_eq!(claimed[1].count, Some(9));
    assert_eq!(claimed[3].kind, OutboxKind::Event);
    assert_eq!(claimed[3].event_type.as_deref(), Some("iam.role.created"));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_claim_stops_at_the_limit_and_skips_published_rows(pool: PgPool) {
    state_row(&pool, 1, "role/a", 1, 1).await;
    state_row(&pool, 2, "role/b", 1, 2).await;
    state_row(&pool, 3, "role/c", 1, 3).await;
    let store = PgOutboxStore::new(pool);
    store
        .mark_published(
            &[published(1, 0)],
            store.current_relay_epoch().await.unwrap(),
            at(NOW),
        )
        .await
        .unwrap();

    let claimed = store.claim_unpublished(1).await.unwrap();

    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].record_key, "role/b");
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn marking_stores_the_offset_the_time_and_the_epoch(pool: PgPool) {
    state_row(&pool, 1, "role/a", 1, 1).await;
    let store = PgOutboxStore::new(pool.clone());
    let epoch = store.current_relay_epoch().await.unwrap();

    store
        .mark_published(&[published(1, 42)], epoch, at(NOW))
        .await
        .unwrap();

    let row = sqlx::query(
        "SELECT published_at, published_offset, relay_epoch FROM iam_outbox WHERE id = $1",
    )
    .bind(id(1))
    .fetch_one(&pool)
    .await
    .unwrap();
    let published_at: OffsetDateTime = row.get("published_at");
    assert_eq!(SystemTime::from(published_at), at(NOW));
    assert_eq!(row.get::<i64, _>("published_offset"), 42);
    assert_eq!(row.get::<i64, _>("relay_epoch"), epoch.value());
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_relay_that_was_replaced_marks_nothing(pool: PgPool) {
    state_row(&pool, 1, "role/a", 1, 1).await;
    let store = PgOutboxStore::new(pool.clone());
    let stale = store.current_relay_epoch().await.unwrap();
    store.take_over_relay().await.unwrap();

    let marked = store
        .mark_published(&[published(1, 0)], stale, at(NOW))
        .await;

    assert!(matches!(marked, Err(RepositoryError::Conflict)));
    assert_eq!(published_count(&pool).await, 0);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_takeover_increments_the_epoch_and_returns_the_latest_published_state_of_every_key(
    pool: PgPool,
) {
    state_row(&pool, 1, "role/a", 1, 1).await;
    state_row(&pool, 2, "role/a", 2, 1).await;
    state_row(&pool, 3, "role/gone", 1, 2).await;
    state_row(&pool, 4, "role/b", 3, 1).await;
    event_row(&pool, 5, 3).await;
    let store = PgOutboxStore::new(pool);
    let epoch = store.current_relay_epoch().await.unwrap();
    store
        .mark_published(
            &[published(1, 0), published(2, 1), published(3, 2)],
            epoch,
            at(NOW),
        )
        .await
        .unwrap();

    let takeover = store.take_over_relay().await.unwrap();

    assert_eq!(
        takeover.epoch,
        RelayEpoch::new(epoch.value().checked_add(1).unwrap()).unwrap()
    );
    let keys: Vec<_> = takeover
        .republish
        .iter()
        .map(|row| (row.record_key.as_str(), row.policy_version.value()))
        .collect();
    assert_eq!(keys, [("role/gone", 1), ("role/a", 2)]);
    assert_eq!(takeover.republish[0].payload, None);
    assert_eq!(store.current_relay_epoch().await.unwrap(), takeover.epoch);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn republished_rows_can_be_marked_again_under_the_new_epoch(pool: PgPool) {
    state_row(&pool, 1, "role/a", 1, 1).await;
    let store = PgOutboxStore::new(pool.clone());
    let first = store.current_relay_epoch().await.unwrap();
    store
        .mark_published(&[published(1, 0)], first, at(NOW))
        .await
        .unwrap();
    let takeover = store.take_over_relay().await.unwrap();

    store
        .mark_published(&[published(1, 7)], takeover.epoch, at(NOW + 1))
        .await
        .unwrap();

    let row = sqlx::query("SELECT published_offset, relay_epoch FROM iam_outbox WHERE id = $1")
        .bind(id(1))
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.get::<i64, _>("published_offset"), 7);
    assert_eq!(row.get::<i64, _>("relay_epoch"), takeover.epoch.value());
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn only_rows_published_before_the_cut_off_are_deleted(pool: PgPool) {
    state_row(&pool, 1, "role/a", 1, 1).await;
    state_row(&pool, 2, "role/b", 1, 2).await;
    state_row(&pool, 3, "role/c", 1, 3).await;
    let store = PgOutboxStore::new(pool.clone());
    let epoch = store.current_relay_epoch().await.unwrap();
    store
        .mark_published(&[published(1, 0)], epoch, at(NOW - 100))
        .await
        .unwrap();
    store
        .mark_published(&[published(2, 1)], epoch, at(NOW))
        .await
        .unwrap();

    let deleted = store.delete_published_before(at(NOW - 10)).await.unwrap();

    assert_eq!(deleted, 1);
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM iam_outbox")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, 2);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_database_that_fails_is_an_unavailable_store(pool: PgPool) {
    let store = PgOutboxStore::new(pool.clone());
    pool.close().await;

    assert!(matches!(
        store.claim_unpublished(1).await,
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        store.current_relay_epoch().await,
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        store.take_over_relay().await,
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        store.delete_published_before(at(NOW)).await,
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        store
            .mark_published(&[], RelayEpoch::new(0).unwrap(), at(NOW))
            .await,
        Err(RepositoryError::Unavailable(_))
    ));
}
