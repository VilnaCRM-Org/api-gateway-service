//! The migrations `create_iam_outbox`, `create_iam_idempotency_keys` and
//! `create_iam_change_receipts`: the columns, the named constraints and indexes, the shape checks
//! of the outbox rows and the down migrations.

use shared_infrastructure::persistence::MIGRATOR;
use sqlx::{PgPool, Row as _};

const TABLES: [&str; 3] = ["iam_outbox", "iam_idempotency_keys", "iam_change_receipts"];

const OBJECTS: &str = "SELECT (to_regclass('iam_outbox') IS NOT NULL)::text, \
    (to_regclass('iam_idempotency_keys') IS NOT NULL)::text, \
    (to_regclass('iam_change_receipts') IS NOT NULL)::text, \
    (to_regclass('iam_security_audit_events') IS NOT NULL)::text, \
    (to_regclass('iam_policy_epoch') IS NOT NULL)::text";

const ID: &str = "0190f2a8-7b3c-7d4e-8f00-000000000001";

fn texts(rows: &[sqlx::postgres::PgRow]) -> Vec<Vec<String>> {
    rows.iter()
        .map(|row| {
            (0..row.len())
                .map(|index| row.get::<String, _>(index))
                .collect()
        })
        .collect()
}

async fn rows(pool: &PgPool, sql: &'static str) -> Vec<Vec<String>> {
    texts(&sqlx::query(sql).fetch_all(pool).await.unwrap())
}

/// The rows of `sql` for the table `table`, bound as the only parameter.
async fn rows_of(pool: &PgPool, sql: &'static str, table: &str) -> Vec<Vec<String>> {
    texts(&sqlx::query(sql).bind(table).fetch_all(pool).await.unwrap())
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

async fn columns(pool: &PgPool, table: &str) -> Vec<Vec<String>> {
    rows_of(
        pool,
        "SELECT column_name::text, data_type::text, is_nullable::text, \
         coalesce(identity_generation::text, '') FROM information_schema.columns \
         WHERE table_schema = current_schema() AND table_name = $1 \
         ORDER BY ordinal_position",
        table,
    )
    .await
}

async fn constraints(pool: &PgPool, table: &str) -> Vec<Vec<String>> {
    rows_of(
        pool,
        "SELECT conname::text, pg_get_constraintdef(oid) FROM pg_constraint \
         WHERE conrelid = $1::regclass ORDER BY conname",
        table,
    )
    .await
}

async fn indexes(pool: &PgPool, table: &str) -> Vec<Vec<String>> {
    rows_of(
        pool,
        "SELECT indexname::text, indexdef::text FROM pg_indexes \
         WHERE tablename = $1 ORDER BY indexname",
        table,
    )
    .await
}

/// The version of the migration whose description contains `name`.
fn version(name: &str) -> i64 {
    MIGRATOR
        .iter()
        .find(|migration| migration.description.contains(name))
        .unwrap()
        .version
}

/// Inserts an outbox row with the given kind and framing columns.
async fn insert_row(
    pool: &PgPool,
    kind: &str,
    payload: Option<&str>,
    seq: Option<i32>,
    event_type: Option<&str>,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        "INSERT INTO iam_outbox (id, kind, topic, record_key, payload, policy_version, seq, count, \
         digest_after, log_epoch, event_type, aggregate_id, occurred_at) \
         VALUES ($1::uuid, $2, 't', 'k', $3, 1, $4, $4, \
         CASE WHEN $4::int IS NULL THEN NULL ELSE decode(repeat('00', 16), 'hex') END, \
         0, $5, CASE WHEN $5::text IS NULL THEN NULL ELSE 'a' END, now())",
    )
    .bind(ID)
    .bind(kind)
    .bind(payload)
    .bind(seq)
    .bind(event_type)
    .execute(pool)
    .await
    .map(|done| done.rows_affected())
}

#[sqlx::test(migrations = false)]
async fn the_outbox_has_every_column_of_the_story(pool: PgPool) {
    MIGRATOR.run(&pool).await.unwrap();

    let outbox = columns(&pool, "iam_outbox").await;

    let expected = [
        ["id", "uuid", "NO", ""],
        ["position", "bigint", "NO", "ALWAYS"],
        ["kind", "text", "NO", ""],
        ["topic", "text", "NO", ""],
        ["record_key", "text", "NO", ""],
        ["payload", "text", "YES", ""],
        ["policy_version", "bigint", "NO", ""],
        ["seq", "integer", "YES", ""],
        ["count", "integer", "YES", ""],
        ["digest_after", "bytea", "YES", ""],
        ["log_epoch", "bigint", "NO", ""],
        ["event_type", "text", "YES", ""],
        ["aggregate_id", "text", "YES", ""],
        ["occurred_at", "timestamp with time zone", "NO", ""],
        ["published_at", "timestamp with time zone", "YES", ""],
        ["published_offset", "bigint", "YES", ""],
        ["relay_epoch", "bigint", "YES", ""],
    ];
    let expected: Vec<Vec<String>> = expected.iter().map(|row| strings(row)).collect();
    assert_eq!(outbox, expected);
}

#[sqlx::test(migrations = false)]
async fn the_idempotency_and_receipt_tables_have_their_columns(pool: PgPool) {
    MIGRATOR.run(&pool).await.unwrap();

    let keys = columns(&pool, "iam_idempotency_keys").await;
    let receipts = columns(&pool, "iam_change_receipts").await;

    let expected_keys = [
        ["actor", "text", "NO", ""],
        ["idempotency_key", "text", "NO", ""],
        ["request_digest", "bytea", "NO", ""],
        ["change_id", "uuid", "NO", ""],
        ["created_at", "timestamp with time zone", "NO", ""],
    ];
    let expected_receipts = [
        ["change_id", "uuid", "NO", ""],
        ["actor", "text", "NO", ""],
        ["target_type", "text", "NO", ""],
        ["target_id", "text", "NO", ""],
        ["entity_version", "bigint", "NO", ""],
        ["policy_version", "bigint", "YES", ""],
        ["created_at", "timestamp with time zone", "NO", ""],
        ["revoked_assignments", "integer", "YES", ""],
    ];
    assert_eq!(
        keys,
        expected_keys
            .iter()
            .map(|row| strings(row))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        receipts,
        expected_receipts
            .iter()
            .map(|row| strings(row))
            .collect::<Vec<_>>()
    );
}

#[sqlx::test(migrations = false)]
async fn the_migrations_name_every_constraint_and_index(pool: PgPool) {
    MIGRATOR.run(&pool).await.unwrap();

    let outbox = constraints(&pool, "iam_outbox").await;
    let keys = constraints(&pool, "iam_idempotency_keys").await;
    let receipts = constraints(&pool, "iam_change_receipts").await;
    let outbox_indexes = indexes(&pool, "iam_outbox").await;
    let key_indexes = indexes(&pool, "iam_idempotency_keys").await;
    let receipt_indexes = indexes(&pool, "iam_change_receipts").await;

    let names =
        |rows: &[Vec<String>]| -> Vec<String> { rows.iter().map(|row| row[0].clone()).collect() };
    assert_eq!(
        names(&outbox),
        strings(&[
            "iam_outbox_digest_after_check",
            "iam_outbox_event_shape_check",
            "iam_outbox_kind_check",
            "iam_outbox_log_epoch_check",
            "iam_outbox_pkey",
            "iam_outbox_policy_version_check",
            "iam_outbox_position_key",
            "iam_outbox_published_check",
            "iam_outbox_relay_epoch_check",
            "iam_outbox_state_framing_check",
        ])
    );
    assert_eq!(outbox[4][1], "PRIMARY KEY (id)");
    assert_eq!(outbox[6][1], "UNIQUE (\"position\")");
    assert_eq!(
        outbox[2][1],
        "CHECK ((kind = ANY (ARRAY['state'::text, 'event'::text])))"
    );
    assert_eq!(
        keys,
        vec![
            strings(&[
                "iam_idempotency_keys_pkey",
                "PRIMARY KEY (actor, idempotency_key)"
            ]),
            strings(&[
                "iam_idempotency_keys_request_digest_check",
                "CHECK ((octet_length(request_digest) = 32))"
            ]),
        ]
    );
    assert_eq!(
        receipts,
        vec![
            strings(&[
                "iam_change_receipts_entity_version_check",
                "CHECK ((entity_version >= 1))"
            ]),
            strings(&["iam_change_receipts_pkey", "PRIMARY KEY (change_id)"]),
            strings(&[
                "iam_change_receipts_policy_version_check",
                "CHECK ((policy_version >= 0))"
            ]),
            strings(&[
                "iam_change_receipts_revoked_assignments_check",
                "CHECK ((revoked_assignments >= 0))"
            ]),
        ]
    );
    assert_eq!(
        names(&outbox_indexes),
        strings(&[
            "iam_outbox_pkey",
            "iam_outbox_policy_version_seq_idx",
            "iam_outbox_position_key",
            "iam_outbox_unpublished_idx",
        ])
    );
    assert!(outbox_indexes[1][1].ends_with("(policy_version, seq)"));
    assert!(
        outbox_indexes[3][1].ends_with("(\"position\") WHERE (published_at IS NULL)"),
        "{}",
        outbox_indexes[3][1]
    );
    assert!(key_indexes[0][1].ends_with("(created_at)"));
    assert!(receipt_indexes[0][1].ends_with("(created_at)"));
}

#[sqlx::test(migrations = false)]
async fn the_outbox_accepts_framed_state_rows_and_complete_event_rows_only(pool: PgPool) {
    MIGRATOR.run(&pool).await.unwrap();

    let unknown_kind = insert_row(&pool, "other", Some("{}"), None, Some("iam.role.created")).await;
    let event_without_type = insert_row(&pool, "event", Some("{}"), None, None).await;
    let event_without_payload =
        insert_row(&pool, "event", None, None, Some("iam.role.created")).await;
    let framed_event = insert_row(
        &pool,
        "event",
        Some("{}"),
        Some(1),
        Some("iam.role.created"),
    )
    .await;
    let unframed_state = insert_row(&pool, "state", Some("{}"), None, None).await;
    let state_with_type = insert_row(
        &pool,
        "state",
        Some("{}"),
        Some(1),
        Some("iam.role.created"),
    )
    .await;
    let tombstone = insert_row(&pool, "state", None, Some(1), None).await;
    sqlx::query("DELETE FROM iam_outbox")
        .execute(&pool)
        .await
        .unwrap();
    let event = insert_row(&pool, "event", Some("{}"), None, Some("iam.role.created")).await;
    let half_published = sqlx::query("UPDATE iam_outbox SET published_at = now()")
        .execute(&pool)
        .await;
    let published = sqlx::query(
        "UPDATE iam_outbox SET published_at = now(), published_offset = 0, relay_epoch = 0",
    )
    .execute(&pool)
    .await;

    for refused in [
        unknown_kind,
        event_without_type,
        event_without_payload,
        framed_event,
        unframed_state,
        state_with_type,
    ] {
        assert!(refused.is_err());
    }
    assert_eq!(tombstone.unwrap(), 1);
    assert_eq!(event.unwrap(), 1);
    assert!(half_published.is_err());
    assert_eq!(published.unwrap().rows_affected(), 1);
}

#[sqlx::test(migrations = false)]
async fn the_down_migrations_drop_the_three_tables_only_and_up_creates_them_again(pool: PgPool) {
    MIGRATOR.run(&pool).await.unwrap();

    MIGRATOR
        .undo(&pool, version("create iam outbox").saturating_sub(1))
        .await
        .unwrap();
    let after_down = rows(&pool, OBJECTS).await;
    MIGRATOR.run(&pool).await.unwrap();
    let after_up = rows(&pool, OBJECTS).await;

    assert_eq!(
        after_down,
        vec![strings(&["false", "false", "false", "true", "true"])]
    );
    assert_eq!(
        after_up,
        vec![strings(&["true", "true", "true", "true", "true"])]
    );
}

#[sqlx::test(migrations = false)]
async fn each_down_migration_drops_its_own_table(pool: PgPool) {
    MIGRATOR.run(&pool).await.unwrap();

    MIGRATOR
        .undo(&pool, version("create iam idempotency keys"))
        .await
        .unwrap();
    let without_receipts = rows(&pool, OBJECTS).await;
    MIGRATOR
        .undo(&pool, version("create iam outbox"))
        .await
        .unwrap();
    let without_keys = rows(&pool, OBJECTS).await;

    assert_eq!(
        without_receipts,
        vec![strings(&["true", "true", "false", "true", "true"])]
    );
    assert_eq!(
        without_keys,
        vec![strings(&["true", "false", "false", "true", "true"])]
    );
}

#[test]
fn every_migration_is_a_reversible_pair_in_story_order() {
    let names = [
        "create iam outbox",
        "create iam idempotency keys",
        "create iam change receipts",
    ];
    for name in names {
        let pair: Vec<bool> = MIGRATOR
            .iter()
            .filter(|migration| migration.version == version(name))
            .map(|migration| migration.migration_type.is_down_migration())
            .collect();
        assert_eq!(pair.len(), 2, "{name}");
        assert!(pair.contains(&true), "{name}");
        assert!(pair.contains(&false), "{name}");
    }
    assert!(version(names[0]) < version(names[1]));
    assert!(version(names[1]) < version(names[2]));
    assert!(version("create iam security audit log") < version(names[0]));
    assert_eq!(TABLES.len(), names.len());
}
