//! `PgAntiEntropyStore`: the policy head, the recently published rows, the newest row of every key
//! written since a point in time, the count of waiting rows and the repair of a lost record.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iam_domain::{AntiEntropyStore as _, OutboxStore as _, PublishedRow, RepositoryError};
use iam_infrastructure::{PgAntiEntropyStore, PgOutboxStore};
use shared_domain::Uuid;
use sqlx::PgPool;
use sqlx::types::Uuid as SqlUuid;

const NOW: u64 = 1_700_000_000;

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn id(number: u128) -> SqlUuid {
    SqlUuid::from_u128(
        0x0190_f2a8_7b3c_7d4e_8f10_0000_0000_0000_u128
            .checked_add(number)
            .unwrap(),
    )
}

async fn state_row(pool: &PgPool, number: u128, key: &str, version: i64, seq: i32) {
    sqlx::query(
        "INSERT INTO iam_outbox (id, kind, topic, record_key, payload, policy_version, seq, count,
            digest_after, log_epoch, occurred_at)
        VALUES ($1, 'state', 'iam.policy.state.v1', $2, '{}', $3, $4, 9,
            decode(repeat('00', 16), 'hex'), 0, now())",
    )
    .bind(id(number))
    .bind(key)
    .bind(version)
    .bind(seq)
    .execute(pool)
    .await
    .unwrap();
}

async fn event_row(pool: &PgPool, number: u128) {
    sqlx::query(
        "INSERT INTO iam_outbox (id, kind, topic, record_key, payload, policy_version, log_epoch,
            event_type, aggregate_id, occurred_at)
        VALUES ($1, 'event', 'iam.events.v1', 'aggregate', '{}', 1, 0, 'iam.role.created',
            'aggregate', now())",
    )
    .bind(id(number))
    .execute(pool)
    .await
    .unwrap();
}

async fn publish(pool: &PgPool, number: u128, offset: i64, seconds: u64) {
    let outbox = PgOutboxStore::new(pool.clone());
    let epoch = outbox.current_relay_epoch().await.unwrap();
    outbox
        .mark_published(
            &[PublishedRow {
                id: Uuid::from_uuid(id(number)),
                offset,
            }],
            epoch,
            at(seconds),
        )
        .await
        .unwrap();
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_head_is_the_version_and_the_digest_of_the_policy_epoch(pool: PgPool) {
    sqlx::query(
        "UPDATE iam_policy_epoch SET version = 7, digest = decode(repeat('ab', 16), 'hex')
        WHERE id = 1",
    )
    .execute(&pool)
    .await
    .unwrap();
    let store = PgAntiEntropyStore::new(pool);

    let head = store.head().await.unwrap();

    assert_eq!(head.version.value(), 7);
    assert_eq!(head.digest.to_hex(), "ab".repeat(16));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_missing_policy_epoch_is_not_found(pool: PgPool) {
    sqlx::query("DELETE FROM iam_policy_epoch")
        .execute(&pool)
        .await
        .unwrap();
    let store = PgAntiEntropyStore::new(pool);

    assert!(matches!(store.head().await, Err(RepositoryError::NotFound)));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_recently_published_rows_come_newest_offset_first_within_the_limit(pool: PgPool) {
    state_row(&pool, 1, "role/a", 1, 1).await;
    state_row(&pool, 2, "role/b", 1, 2).await;
    state_row(&pool, 3, "role/c", 1, 3).await;
    event_row(&pool, 4).await;
    publish(&pool, 1, 10, NOW - 100).await;
    publish(&pool, 2, 11, NOW).await;
    publish(&pool, 3, 12, NOW).await;
    let store = PgAntiEntropyStore::new(pool);

    let recent = store.recently_published(at(NOW - 50), 5).await.unwrap();
    let limited = store.recently_published(at(0), 2).await.unwrap();

    let keys: Vec<_> = recent.iter().map(|row| row.key.as_str()).collect();
    assert_eq!(keys, ["role/c", "role/b"]);
    assert_eq!(recent[0].offset, 12);
    assert_eq!(recent[0].version.value(), 1);
    assert_eq!(recent[0].id.as_uuid(), id(3));
    assert_eq!(limited.len(), 2);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_written_keys_carry_their_newest_row_and_its_offset(pool: PgPool) {
    state_row(&pool, 1, "role/a", 1, 1).await;
    state_row(&pool, 2, "role/a", 2, 1).await;
    state_row(&pool, 3, "role/b", 2, 2).await;
    event_row(&pool, 4).await;
    publish(&pool, 2, 21, NOW).await;
    let store = PgAntiEntropyStore::new(pool);

    let mut written = store.keys_written_since(at(0)).await.unwrap();
    let none = store.keys_written_since(at(NOW * 10)).await.unwrap();

    written.sort_by(|left, right| left.key.cmp(&right.key));
    assert_eq!(written.len(), 2);
    assert_eq!(written[0].key, "role/a");
    assert_eq!(written[0].version.value(), 2);
    assert_eq!(written[0].published_offset, Some(21));
    assert_eq!(written[1].key, "role/b");
    assert_eq!(written[1].published_offset, None);
    assert_eq!(none.len(), 0);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_waiting_state_rows_are_counted(pool: PgPool) {
    state_row(&pool, 1, "role/a", 1, 1).await;
    state_row(&pool, 2, "role/b", 1, 2).await;
    event_row(&pool, 3).await;
    publish(&pool, 1, 0, NOW).await;
    let store = PgAntiEntropyStore::new(pool);

    assert_eq!(store.unpublished_count().await.unwrap(), 1);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_republished_row_goes_back_to_the_unpublished_rows(pool: PgPool) {
    state_row(&pool, 1, "role/a", 1, 1).await;
    publish(&pool, 1, 5, NOW).await;
    let store = PgAntiEntropyStore::new(pool.clone());
    let row = Uuid::from_uuid(id(1));

    assert!(store.republish(row).await.unwrap());

    let outbox = PgOutboxStore::new(pool);
    let claimed = outbox.claim_unpublished(10).await.unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].record_key, "role/a");
    assert!(!store.republish(row).await.unwrap());
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_row_the_outbox_no_longer_holds_cannot_be_republished(pool: PgPool) {
    let store = PgAntiEntropyStore::new(pool);

    assert!(!store.republish(Uuid::from_uuid(id(99))).await.unwrap());
}
