//! `PgMaintenanceStore`: the orphaned grants that are old enough, the expired records that go and
//! the anchoring of the audit chain in the outbox.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iam_domain::{
    AnchorStamp, MaintenanceStore as _, RepositoryError, RetentionCutoffs, SecurityAuditLog as _,
};
use iam_infrastructure::{PgMaintenanceStore, PgSecurityAuditLog};
use serde_json::Value;
use shared_domain::Uuid;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;
use sqlx::{AssertSqlSafe, PgPool, Row as _};
use test_support::security_audit::security_audit_event;
use test_support::seed::TestRng;
use test_support::unit_of_work::uuid_v7;

const NOW: u64 = 1_700_000_000;
const RETENTION: Duration = Duration::from_hours(2_160);

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn timestamp(time: SystemTime) -> OffsetDateTime {
    OffsetDateTime::from(time)
}

/// Inserts a role and returns its identifier; `deleted` marks it deleted.
async fn seed_role(pool: &PgPool, rng: &mut TestRng, deleted: bool) -> SqlUuid {
    let id = uuid_v7(rng).as_uuid();
    sqlx::query(
        "INSERT INTO iam_roles (id, name, kind, grant_count, version, created_at, updated_at,
            deleted_at)
        VALUES ($1, $2, 'custom', 0, 1, now(), now(), CASE WHEN $3 THEN now() END)",
    )
    .bind(id)
    .bind(format!("role-{id}"))
    .bind(deleted)
    .execute(pool)
    .await
    .unwrap();
    id
}

/// Inserts a grant of the role; an `orphaned_at` makes it inactive.
async fn seed_grant(pool: &PgPool, role: SqlUuid, key: &str, orphaned_at: Option<SystemTime>) {
    sqlx::query(
        "INSERT INTO iam_role_permissions (role_id, permission_key, key_kind, service, is_wildcard,
            active, orphaned_at, granted_by, granted_at)
        VALUES ($1, $2, 'rest', 'billing', FALSE, $3, $4, 'system:test', now())",
    )
    .bind(role)
    .bind(key)
    .bind(orphaned_at.is_none())
    .bind(orphaned_at.map(timestamp))
    .execute(pool)
    .await
    .unwrap();
}

async fn count(pool: &PgPool, table: &'static str) -> i64 {
    sqlx::query_scalar(AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn only_inactive_grants_of_live_roles_orphaned_strictly_before_the_instant_are_found(
    pool: PgPool,
) {
    let mut rng = TestRng::from_env();
    let live = seed_role(&pool, &mut rng, false).await;
    let deleted = seed_role(&pool, &mut rng, true).await;
    seed_grant(&pool, live, "rest:billing:GET /active", None).await;
    seed_grant(&pool, live, "rest:billing:GET /old", Some(at(NOW - 20))).await;
    seed_grant(&pool, live, "rest:billing:GET /older", Some(at(NOW - 30))).await;
    seed_grant(&pool, live, "rest:billing:GET /boundary", Some(at(NOW))).await;
    seed_grant(&pool, live, "rest:billing:GET /young", Some(at(NOW + 10))).await;
    seed_grant(
        &pool,
        deleted,
        "rest:billing:GET /deleted",
        Some(at(NOW - 40)),
    )
    .await;
    let store = PgMaintenanceStore::new(pool);

    let found = store.expired_orphaned_grants(at(NOW), 10).await.unwrap();

    let keys: Vec<String> = found
        .iter()
        .map(|orphan| orphan.grant.to_string())
        .collect();
    assert_eq!(keys, ["rest:billing:GET /older", "rest:billing:GET /old"]);
    assert_eq!(found[0].role_id.as_uuid().as_uuid(), live);
    assert_eq!(found[0].orphaned_at, at(NOW - 30));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_search_for_orphaned_grants_stops_at_the_limit(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let live = seed_role(&pool, &mut rng, false).await;
    for (index, key) in [
        "rest:billing:GET /a",
        "rest:billing:GET /b",
        "rest:billing:GET /c",
    ]
    .into_iter()
    .enumerate()
    {
        seed_grant(
            &pool,
            live,
            key,
            Some(at(NOW
                .checked_sub(100)
                .and_then(|base| base.checked_add(u64::try_from(index).unwrap()))
                .unwrap())),
        )
        .await;
    }
    let store = PgMaintenanceStore::new(pool);

    let found = store.expired_orphaned_grants(at(NOW), 2).await.unwrap();

    let keys: Vec<String> = found
        .iter()
        .map(|orphan| orphan.grant.to_string())
        .collect();
    assert_eq!(keys, ["rest:billing:GET /a", "rest:billing:GET /b"]);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_stored_key_that_is_no_grant_makes_the_search_fail(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let live = seed_role(&pool, &mut rng, false).await;
    seed_grant(&pool, live, "not a key", Some(at(NOW - 5))).await;
    let store = PgMaintenanceStore::new(pool);

    let error = store
        .expired_orphaned_grants(at(NOW), 10)
        .await
        .unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}

/// Inserts an idempotency record, a change receipt and an inbound-event id, each created at `time`.
async fn seed_records(pool: &PgPool, rng: &mut TestRng, time: SystemTime) {
    let change = uuid_v7(rng).as_uuid();
    sqlx::query(
        "INSERT INTO iam_idempotency_keys (actor, idempotency_key, request_digest, change_id,
            created_at)
        VALUES ('system:test', $1, decode(repeat('00', 32), 'hex'), $2, $3)",
    )
    .bind(format!("key-{change}"))
    .bind(change)
    .bind(timestamp(time))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO iam_change_receipts (change_id, actor, target_type, target_id,
            entity_version, created_at)
        VALUES ($1, 'system:test', 'role', 'r', 1, $2)",
    )
    .bind(change)
    .bind(timestamp(time))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO iam_inbound_events (event_id, topic, partition, \"offset\", event_type,
            outcome, processed_at)
        VALUES ($1, 'user-events', 0, 1, 'SessionRevoked', 'applied', $2)",
    )
    .bind(change)
    .bind(timestamp(time))
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn records_older_than_their_cutoff_are_removed_and_younger_ones_stay(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let cutoffs = RetentionCutoffs::at(at(NOW), RETENTION);
    seed_records(
        &pool,
        &mut rng,
        cutoffs
            .inbound_events
            .checked_sub(Duration::from_secs(1))
            .unwrap(),
    )
    .await;
    seed_records(
        &pool,
        &mut rng,
        cutoffs
            .idempotency_records
            .checked_sub(Duration::from_secs(1))
            .unwrap(),
    )
    .await;
    seed_records(&pool, &mut rng, cutoffs.idempotency_records).await;
    seed_records(&pool, &mut rng, at(NOW)).await;
    let store = PgMaintenanceStore::new(pool.clone());

    let purged = store.purge_expired_records(&cutoffs).await.unwrap();

    assert_eq!(purged.idempotency_records, 2);
    assert_eq!(purged.change_receipts, 2);
    assert_eq!(purged.inbound_events, 1);
    assert_eq!(count(&pool, "iam_idempotency_keys").await, 2);
    assert_eq!(count(&pool, "iam_change_receipts").await, 2);
    assert_eq!(count(&pool, "iam_inbound_events").await, 3);
}

/// The tables of the expired records, in the order the purge deletes from them.
const RECORD_TABLES: [&str; 3] = [
    "iam_idempotency_keys",
    "iam_change_receipts",
    "iam_inbound_events",
];

/// Drops `table`, so that its delete fails: the purge is unavailable and the transaction leaves
/// the old records of the other tables in place.
async fn assert_purge_fails_without(pool: &PgPool, table: &'static str) {
    let mut rng = TestRng::from_env();
    seed_records(pool, &mut rng, at(1)).await;
    sqlx::query(AssertSqlSafe(format!("DROP TABLE {table} CASCADE")))
        .execute(pool)
        .await
        .unwrap();
    let store = PgMaintenanceStore::new(pool.clone());

    let outcome = store
        .purge_expired_records(&RetentionCutoffs::at(at(NOW), RETENTION))
        .await;

    assert!(matches!(outcome, Err(RepositoryError::Unavailable(_))));
    for other in RECORD_TABLES.into_iter().filter(|other| *other != table) {
        assert_eq!(count(pool, other).await, 1, "{other}");
    }
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_failed_delete_of_idempotency_records_purges_nothing(pool: PgPool) {
    assert_purge_fails_without(&pool, "iam_idempotency_keys").await;
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_failed_delete_of_change_receipts_purges_nothing(pool: PgPool) {
    assert_purge_fails_without(&pool, "iam_change_receipts").await;
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_failed_delete_of_inbound_events_purges_nothing(pool: PgPool) {
    assert_purge_fails_without(&pool, "iam_inbound_events").await;
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn session_revocations_and_cutoffs_of_any_age_stay(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let user = uuid_v7(&mut rng).as_uuid();
    sqlx::query(
        "INSERT INTO iam_revoked_sessions (session_id, id, user_id, source, revoked_by, revoked_at,
            prune_after)
        VALUES ('session-1', $1, $2, 'operator', 'system:test', $3, $3)",
    )
    .bind(uuid_v7(&mut rng).as_uuid())
    .bind(user)
    .bind(timestamp(UNIX_EPOCH))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO iam_user_token_validity (user_id, tokens_valid_after, source, updated_at,
            prune_after)
        VALUES ($1, $2, 'operator', $2, $2)",
    )
    .bind(user)
    .bind(timestamp(UNIX_EPOCH))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO iam_global_token_cutoff (id, tokens_valid_after, set_by, set_at)
        VALUES (1, $1, 'system:test', $1)",
    )
    .bind(timestamp(UNIX_EPOCH))
    .execute(&pool)
    .await
    .unwrap();
    let store = PgMaintenanceStore::new(pool.clone());

    let purged = store
        .purge_expired_records(&RetentionCutoffs::at(at(NOW), Duration::from_secs(1)))
        .await
        .unwrap();

    assert_eq!(purged.total(), 0);
    assert_eq!(count(&pool, "iam_revoked_sessions").await, 1);
    assert_eq!(count(&pool, "iam_user_token_validity").await, 1);
    assert_eq!(count(&pool, "iam_global_token_cutoff").await, 1);
}

fn stamp(rng: &mut TestRng) -> AnchorStamp {
    AnchorStamp {
        event_id: uuid_v7(rng),
        occurred_at: at(NOW),
    }
}

/// The encoded envelope of the outbox row of an anchoring.
async fn anchor_payload(pool: &PgPool, id: Uuid) -> String {
    sqlx::query_scalar("SELECT payload FROM iam_outbox WHERE id = $1")
        .bind(id.as_uuid())
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Checks the columns of the outbox row of an anchoring except its payload.
async fn assert_anchor_row(pool: &PgPool, id: Uuid) {
    let row = sqlx::query(
        "SELECT kind, topic, record_key, policy_version, log_epoch, event_type, aggregate_id,
            published_at FROM iam_outbox WHERE id = $1",
    )
    .bind(id.as_uuid())
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("kind"), "event");
    assert_eq!(row.get::<String, _>("topic"), "iam.events.v1");
    assert_eq!(
        row.get::<String, _>("event_type"),
        "iam.security_audit.anchored"
    );
    assert_eq!(row.get::<String, _>("record_key"), id.to_string());
    assert_eq!(row.get::<String, _>("aggregate_id"), id.to_string());
    assert_eq!(row.get::<i64, _>("policy_version"), 0);
    assert_eq!(row.get::<i64, _>("log_epoch"), 0);
    assert!(
        row.get::<Option<OffsetDateTime>, _>("published_at")
            .is_none()
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_anchoring_writes_the_head_of_the_chain_into_the_outbox(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let head = PgSecurityAuditLog::new(pool.clone())
        .append_batch(&[
            security_audit_event(&mut rng),
            security_audit_event(&mut rng),
        ])
        .await
        .unwrap();
    let stamp = stamp(&mut rng);
    let store = PgMaintenanceStore::new(pool.clone());

    let anchored = store.anchor_audit_chain(stamp).await.unwrap();

    assert_eq!(anchored, head);
    assert_eq!(anchored.seq(), 2);
    assert_anchor_row(&pool, stamp.event_id).await;
    let payload: Value =
        serde_json::from_str(&anchor_payload(&pool, stamp.event_id).await).unwrap();
    assert_eq!(payload["type"], "iam.security_audit.anchored");
    assert_eq!(payload["data"]["seq"], 2);
    assert_eq!(payload["data"]["hash"], anchored.hash().to_string());
    assert_eq!(payload["data"]["actor"], "system:maintenance");
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_empty_chain_is_anchored_at_its_genesis_head(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let store = PgMaintenanceStore::new(pool.clone());

    let anchored = store.anchor_audit_chain(stamp(&mut rng)).await.unwrap();

    assert_eq!(anchored.seq(), 0);
    assert_eq!(count(&pool, "iam_outbox").await, 1);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_event_id_that_is_stored_already_is_a_duplicate_and_writes_nothing(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let stamp = stamp(&mut rng);
    let store = PgMaintenanceStore::new(pool.clone());
    store.anchor_audit_chain(stamp).await.unwrap();

    let error = store.anchor_audit_chain(stamp).await.unwrap_err();

    assert!(matches!(error, RepositoryError::AlreadyExists));
    assert_eq!(count(&pool, "iam_outbox").await, 1);
}
