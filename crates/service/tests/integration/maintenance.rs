//! The maintenance task against PostgreSQL: expired orphaned grants and records go with an audit
//! record each, revocations stay, the audit chain head is anchored in the outbox, and of two
//! replicas only the lock holder runs a batch.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iam_application::{
    BatchOutcome, MaintenanceSettings, PolicyMaintenance, RunMaintenanceCommand,
    RunMaintenanceCommandHandler,
};
use iam_domain::{Leadership, SingletonLeadership as _};
use iam_infrastructure::{
    AdvisoryLockLeadership, PgIamUnitOfWork, PgMaintenanceStore, PgRoleRepository,
    PgTaskStateRepository,
};
use serde_json::Value;
use shared_domain::CommandHandler as _;
use shared_infrastructure::id::UuidV7Generator;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;
use sqlx::{AssertSqlSafe, PgPool, Row as _};
use test_support::clock::FixedClock;
use test_support::seed::TestRng;
use test_support::unit_of_work::uuid_v7;

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;
const RETENTION: Duration = Duration::from_hours(2_160);
const FRESH: &str = "rest:billing:GET /fresh";
const OLD: &str = "rest:billing:GET /old";
const OLDER: &str = "rest:billing:GET /older";
const YOUNG: &str = "rest:billing:GET /young";

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn ago(days: u64) -> SystemTime {
    at(NOW.checked_sub(days.checked_mul(DAY).unwrap()).unwrap())
}

fn settings() -> MaintenanceSettings {
    MaintenanceSettings {
        interval: Duration::from_mins(10),
        orphaned_grant_retention: RETENTION,
    }
}

fn handler(pool: &PgPool) -> RunMaintenanceCommandHandler {
    RunMaintenanceCommandHandler::new(
        Arc::new(PgMaintenanceStore::new(pool.clone())),
        Arc::new(PgRoleRepository::new(pool.clone())),
        Arc::new(PgIamUnitOfWork::new(pool.clone())),
        Arc::new(FixedClock::at(at(NOW))),
        Arc::new(UuidV7Generator),
    )
}

async fn run(pool: &PgPool) {
    handler(pool)
        .handle(RunMaintenanceCommand {
            orphaned_grant_retention: RETENTION,
        })
        .await
        .unwrap();
}

/// Inserts a role and returns its identifier.
async fn seed_role(pool: &PgPool, rng: &mut TestRng, grants: usize) -> SqlUuid {
    let id = uuid_v7(rng).as_uuid();
    sqlx::query(
        "INSERT INTO iam_roles (id, name, kind, grant_count, version, created_at, updated_at)
        VALUES ($1, $2, 'custom', $3, 1, now(), now())",
    )
    .bind(id)
    .bind(format!("role-{id}"))
    .bind(i32::try_from(grants).unwrap())
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
    .bind(orphaned_at.map(OffsetDateTime::from))
    .execute(pool)
    .await
    .unwrap();
}

/// A role that holds one active grant, one grant orphaned `old` days ago and one orphaned `young`
/// days ago.
async fn seed_billing_role(pool: &PgPool, rng: &mut TestRng, old: u64, young: u64) -> SqlUuid {
    let role = seed_role(pool, rng, 3).await;
    seed_grant(pool, role, FRESH, None).await;
    seed_grant(pool, role, OLD, Some(ago(old))).await;
    seed_grant(pool, role, YOUNG, Some(ago(young))).await;
    role
}

async fn grants_of(pool: &PgPool, role: SqlUuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT permission_key FROM iam_role_permissions WHERE role_id = $1
        ORDER BY permission_key",
    )
    .bind(role)
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn count(pool: &PgPool, table: &'static str) -> i64 {
    sqlx::query_scalar(AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn orphaned_grants_older_than_the_retention_are_purged_with_an_audit_record_each(
    pool: PgPool,
) {
    let mut rng = TestRng::from_env();
    let role = seed_role(&pool, &mut rng, 4).await;
    seed_grant(&pool, role, FRESH, None).await;
    seed_grant(&pool, role, OLD, Some(ago(91))).await;
    seed_grant(&pool, role, OLDER, Some(ago(200))).await;
    seed_grant(&pool, role, YOUNG, Some(ago(89))).await;

    run(&pool).await;

    assert_eq!(grants_of(&pool, role).await, [FRESH, YOUNG]);
    let audits: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT action, target_id, before_summary FROM iam_security_audit_events
        WHERE action = 'role.orphaned_grant.purged' ORDER BY seq",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(audits.len(), 2);
    for (action, target, _before) in &audits {
        assert_eq!(action, "role.orphaned_grant.purged");
        assert_eq!(target, &role.to_string());
    }
    let summaries: String = audits
        .iter()
        .filter_map(|(_action, _target, before)| before.clone())
        .collect();
    assert!(
        summaries.contains(OLD) && summaries.contains(OLDER),
        "{summaries}"
    );
    assert!(!summaries.contains(YOUNG), "{summaries}");
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_role_state_changes_in_the_same_transaction_as_the_purge(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let role = seed_billing_role(&pool, &mut rng, 91, 89).await;

    run(&pool).await;

    let (version, grant_count): (i64, i32) =
        sqlx::query_as("SELECT version, grant_count FROM iam_roles WHERE id = $1")
            .bind(role)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!((version, grant_count), (2, 2));
    let policy_version: i64 =
        sqlx::query_scalar("SELECT version FROM iam_policy_epoch WHERE id = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(policy_version, 1);
    let changed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM iam_outbox
        WHERE event_type = 'iam.role_permissions.changed' AND aggregate_id = $1
            AND policy_version = 1",
    )
    .bind(role.to_string())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(changed, 1);
    let receipts = count(&pool, "iam_change_receipts").await;
    assert_eq!(receipts, 1);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_role_without_expired_grants_is_left_alone(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let role = seed_billing_role(&pool, &mut rng, 89, 10).await;

    run(&pool).await;

    assert_eq!(grants_of(&pool, role).await, [FRESH, OLD, YOUNG]);
    assert_eq!(count(&pool, "iam_security_audit_events").await, 0);
    let version: i64 = sqlx::query_scalar("SELECT version FROM iam_roles WHERE id = $1")
        .bind(role)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(version, 1);
}

/// Inserts an idempotency record, a change receipt and an inbound-event id created `hours` ago.
async fn seed_records(pool: &PgPool, rng: &mut TestRng, hours: u64) {
    let change = uuid_v7(rng).as_uuid();
    let created = at(NOW.checked_sub(hours.checked_mul(3_600).unwrap()).unwrap());
    sqlx::query(
        "INSERT INTO iam_idempotency_keys (actor, idempotency_key, request_digest, change_id,
            created_at)
        VALUES ('system:test', $1, decode(repeat('00', 32), 'hex'), $2, $3)",
    )
    .bind(format!("key-{change}"))
    .bind(change)
    .bind(OffsetDateTime::from(created))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO iam_change_receipts (change_id, actor, target_type, target_id,
            entity_version, created_at)
        VALUES ($1, 'system:test', 'role', 'r', 1, $2)",
    )
    .bind(change)
    .bind(OffsetDateTime::from(created))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO iam_inbound_events (event_id, topic, partition, \"offset\", event_type,
            outcome, processed_at)
        VALUES ($1, 'user-events', 0, 1, 'SessionRevoked', 'applied', $2)",
    )
    .bind(change)
    .bind(OffsetDateTime::from(created))
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn records_older_than_their_window_are_removed_and_younger_ones_remain(pool: PgPool) {
    let mut rng = TestRng::from_env();
    seed_records(&pool, &mut rng, 25).await;
    seed_records(&pool, &mut rng, 23).await;
    seed_records(&pool, &mut rng, 8 * 24).await;
    seed_records(&pool, &mut rng, 6 * 24).await;

    run(&pool).await;

    assert_eq!(count(&pool, "iam_idempotency_keys").await, 1);
    assert_eq!(count(&pool, "iam_change_receipts").await, 1);
    assert_eq!(count(&pool, "iam_inbound_events").await, 3);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn session_revocations_and_cutoffs_of_any_age_are_not_removed(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let user = uuid_v7(&mut rng).as_uuid();
    let long_ago = OffsetDateTime::from(UNIX_EPOCH);
    sqlx::query(
        "INSERT INTO iam_revoked_sessions (session_id, id, user_id, source, revoked_by, revoked_at,
            prune_after)
        VALUES ('session-1', $1, $2, 'operator', 'system:test', $3, $3)",
    )
    .bind(uuid_v7(&mut rng).as_uuid())
    .bind(user)
    .bind(long_ago)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO iam_user_token_validity (user_id, tokens_valid_after, source, updated_at,
            prune_after)
        VALUES ($1, $2, 'operator', $2, $2)",
    )
    .bind(user)
    .bind(long_ago)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO iam_global_token_cutoff (id, tokens_valid_after, set_by, set_at)
        VALUES (1, $1, 'system:test', $1)",
    )
    .bind(long_ago)
    .execute(&pool)
    .await
    .unwrap();

    run(&pool).await;

    assert_eq!(count(&pool, "iam_revoked_sessions").await, 1);
    assert_eq!(count(&pool, "iam_user_token_validity").await, 1);
    assert_eq!(count(&pool, "iam_global_token_cutoff").await, 1);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_run_puts_one_anchoring_event_with_the_current_chain_head_in_the_outbox(pool: PgPool) {
    let mut rng = TestRng::from_env();
    seed_billing_role(&pool, &mut rng, 91, 89).await;

    run(&pool).await;

    let (head_seq, head_hash): (i64, String) = sqlx::query_as(
        "SELECT seq, encode(hash, 'hex') FROM iam_security_audit_chain_head WHERE id = 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(head_seq, 1);
    let rows = sqlx::query(
        "SELECT payload, published_at IS NULL AS pending FROM iam_outbox
        WHERE event_type = 'iam.security_audit.anchored'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].get::<bool, _>("pending"));
    let payload: Value = serde_json::from_str(&rows[0].get::<String, _>("payload")).unwrap();
    assert_eq!(payload["data"]["seq"], head_seq);
    assert_eq!(payload["data"]["hash"], head_hash);
    assert_eq!(payload["data"]["actor"], "system:maintenance");
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn every_run_anchors_the_head_again(pool: PgPool) {
    run(&pool).await;
    run(&pool).await;

    let anchors: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM iam_outbox WHERE event_type = 'iam.security_audit.anchored'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(anchors, 2);
}

fn replica(pool: &PgPool) -> iam_application::SingletonLoop {
    let task = PolicyMaintenance::new(
        handler(pool),
        Arc::new(PgTaskStateRepository::new(pool.clone())),
        settings(),
    );
    task.into_loop(
        Arc::new(AdvisoryLockLeadership::new(pool.clone())),
        Arc::new(FixedClock::at(at(NOW))),
    )
    .unwrap()
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn only_the_lock_holder_runs_the_batch(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let role = seed_billing_role(&pool, &mut rng, 91, 89).await;
    let leadership = AdvisoryLockLeadership::new(pool.clone());
    let Leadership::Leader(holder) = leadership.begin(&PolicyMaintenance::TASK).await.unwrap()
    else {
        panic!("the first replica must lead");
    };

    let skipped = replica(&pool).run_batch().await;

    assert_eq!(skipped, BatchOutcome::Skipped);
    assert_eq!(grants_of(&pool, role).await, [FRESH, OLD, YOUNG]);
    assert_eq!(count(&pool, "iam_outbox").await, 0);
    holder.rollback().await.unwrap();

    let committed = replica(&pool).run_batch().await;

    assert_eq!(committed, BatchOutcome::Committed);
    assert_eq!(grants_of(&pool, role).await, [FRESH, YOUNG]);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_second_batch_within_the_interval_runs_nothing(pool: PgPool) {
    let replica = replica(&pool);
    assert_eq!(replica.run_batch().await, BatchOutcome::Committed);
    let anchors = count(&pool, "iam_outbox").await;

    let again = replica.run_batch().await;

    assert_eq!(again, BatchOutcome::Skipped);
    assert_eq!(count(&pool, "iam_outbox").await, anchors);
    let runs: i64 = sqlx::query_scalar(
        "SELECT run_count FROM iam_task_state WHERE task_name = 'policy-maintenance'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(runs, 1);
}
