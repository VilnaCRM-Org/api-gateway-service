//! The migration `create_iam_security_audit_log`: the two tables, their named constraints and
//! indexes, the seeded chain head, the append-only triggers and the down migration.

use shared_infrastructure::persistence::MIGRATOR;
use sqlx::{PgPool, Row as _};

const COLUMNS: &str = "SELECT table_name::text, column_name::text, data_type::text, \
    is_nullable::text FROM information_schema.columns \
    WHERE table_schema = current_schema() \
    AND table_name IN ('iam_security_audit_events', 'iam_security_audit_chain_head') \
    ORDER BY table_name, ordinal_position";

const CONSTRAINTS: &str = "SELECT conname::text, pg_get_constraintdef(oid) FROM pg_constraint \
    WHERE conrelid IN ('iam_security_audit_events'::regclass, \
    'iam_security_audit_chain_head'::regclass) ORDER BY conname";

const INDEXES: &str = "SELECT indexname::text, indexdef::text FROM pg_indexes \
    WHERE tablename = 'iam_security_audit_events' ORDER BY indexname";

const TRIGGERS: &str = "SELECT tgname::text FROM pg_trigger \
    WHERE tgrelid = 'iam_security_audit_events'::regclass AND NOT tgisinternal ORDER BY tgname";

const HEAD: &str =
    "SELECT id::text, seq::text, encode(hash, 'hex') FROM iam_security_audit_chain_head";

const OBJECTS: &str = "SELECT (to_regclass('iam_security_audit_events') IS NOT NULL)::text, \
    (to_regclass('iam_security_audit_chain_head') IS NOT NULL)::text, \
    (to_regproc('iam_security_audit_events_reject_change') IS NOT NULL)::text, \
    (to_regclass('iam_policy_epoch') IS NOT NULL)::text";

async fn rows(pool: &PgPool, sql: &'static str) -> Vec<Vec<String>> {
    let rows = sqlx::query(sql).fetch_all(pool).await.unwrap();
    rows.iter()
        .map(|row| {
            (0..row.len())
                .map(|index| row.get::<String, _>(index))
                .collect()
        })
        .collect()
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

/// The version of the migration that creates the audit tables.
fn version() -> i64 {
    MIGRATOR
        .iter()
        .find(|migration| {
            migration
                .description
                .contains("create iam security audit log")
        })
        .unwrap()
        .version
}

#[sqlx::test(migrations = false)]
async fn the_migration_creates_both_tables_with_their_columns(pool: PgPool) {
    MIGRATOR.run(&pool).await.unwrap();

    let columns = rows(&pool, COLUMNS).await;

    let head = [
        ["iam_security_audit_chain_head", "id", "smallint", "NO"],
        ["iam_security_audit_chain_head", "seq", "bigint", "NO"],
        ["iam_security_audit_chain_head", "hash", "bytea", "NO"],
    ];
    let events = [
        ("seq", "bigint", "NO"),
        ("id", "uuid", "NO"),
        ("occurred_at", "timestamp with time zone", "NO"),
        ("actor", "text", "NO"),
        ("caller_service", "text", "YES"),
        ("action", "text", "NO"),
        ("target_type", "text", "NO"),
        ("target_id", "text", "NO"),
        ("scope", "text", "YES"),
        ("before_summary", "text", "YES"),
        ("after_summary", "text", "YES"),
        ("idempotency_key", "text", "YES"),
        ("outcome", "text", "NO"),
        ("reason", "text", "YES"),
        ("policy_version", "bigint", "YES"),
        ("request_id", "text", "YES"),
        ("prev_hash", "bytea", "NO"),
        ("hash", "bytea", "NO"),
    ];
    let mut expected: Vec<Vec<String>> = head.iter().map(|row| strings(row)).collect();
    expected.extend(events.iter().map(|(name, data_type, nullable)| {
        strings(&["iam_security_audit_events", name, data_type, nullable])
    }));
    assert_eq!(columns, expected);
}

#[sqlx::test(migrations = false)]
async fn the_migration_names_every_constraint_index_and_trigger(pool: PgPool) {
    MIGRATOR.run(&pool).await.unwrap();

    let constraints = rows(&pool, CONSTRAINTS).await;
    let indexes = rows(&pool, INDEXES).await;
    let triggers = rows(&pool, TRIGGERS).await;

    assert_eq!(
        constraints,
        vec![
            strings(&[
                "iam_security_audit_chain_head_hash_check",
                "CHECK ((octet_length(hash) = 32))"
            ]),
            strings(&["iam_security_audit_chain_head_id_check", "CHECK ((id = 1))"]),
            strings(&["iam_security_audit_chain_head_pkey", "PRIMARY KEY (id)"]),
            strings(&[
                "iam_security_audit_chain_head_seq_check",
                "CHECK ((seq >= 0))"
            ]),
            strings(&[
                "iam_security_audit_events_hash_check",
                "CHECK ((octet_length(hash) = 32))"
            ]),
            strings(&["iam_security_audit_events_id_key", "UNIQUE (id)"]),
            strings(&[
                "iam_security_audit_events_outcome_check",
                "CHECK ((outcome = ANY (ARRAY['committed'::text, 'rejected'::text])))"
            ]),
            strings(&["iam_security_audit_events_pkey", "PRIMARY KEY (seq)"]),
            strings(&[
                "iam_security_audit_events_policy_version_check",
                "CHECK ((policy_version >= 0))"
            ]),
            strings(&[
                "iam_security_audit_events_prev_hash_check",
                "CHECK ((octet_length(prev_hash) = 32))"
            ]),
            strings(&["iam_security_audit_events_seq_check", "CHECK ((seq >= 1))"]),
        ]
    );
    let index_names: Vec<&str> = indexes.iter().map(|row| row[0].as_str()).collect();
    assert_eq!(
        index_names,
        vec![
            "iam_security_audit_events_actor_occurred_at_idx",
            "iam_security_audit_events_id_key",
            "iam_security_audit_events_occurred_at_idx",
            "iam_security_audit_events_pkey",
            "iam_security_audit_events_target_idx",
        ]
    );
    assert!(indexes[0][1].ends_with("(actor, occurred_at)"));
    assert!(indexes[2][1].ends_with("(occurred_at)"));
    assert!(indexes[4][1].ends_with("(target_type, target_id)"));
    assert_eq!(
        triggers,
        vec![
            strings(&["iam_security_audit_events_append_only"]),
            strings(&["iam_security_audit_events_no_truncate"]),
        ]
    );
}

#[sqlx::test(migrations = false)]
async fn the_migration_seeds_the_genesis_chain_head(pool: PgPool) {
    MIGRATOR.run(&pool).await.unwrap();

    let head = rows(&pool, HEAD).await;

    assert_eq!(head, vec![strings(&["1", "0", &"0".repeat(64)])]);
}

#[sqlx::test(migrations = false)]
async fn the_chain_head_holds_exactly_the_row_with_id_1(pool: PgPool) {
    MIGRATOR.run(&pool).await.unwrap();

    let second =
        sqlx::query("INSERT INTO iam_security_audit_chain_head (id, seq, hash) VALUES (2, 0, $1)")
            .bind(vec![0_u8; 32])
            .execute(&pool)
            .await;
    let short_hash = sqlx::query("UPDATE iam_security_audit_chain_head SET hash = $1")
        .bind(vec![0_u8; 31])
        .execute(&pool)
        .await;
    let negative = sqlx::query("UPDATE iam_security_audit_chain_head SET seq = -1")
        .execute(&pool)
        .await;

    assert!(second.is_err());
    assert!(short_hash.is_err());
    assert!(negative.is_err());
}

#[sqlx::test(migrations = false)]
async fn the_down_migration_drops_the_audit_objects_only_and_up_creates_them_again(pool: PgPool) {
    MIGRATOR.run(&pool).await.unwrap();

    MIGRATOR
        .undo(&pool, version().saturating_sub(1))
        .await
        .unwrap();
    let after_down = rows(&pool, OBJECTS).await;
    MIGRATOR.run(&pool).await.unwrap();
    let after_up = rows(&pool, OBJECTS).await;
    let head = rows(&pool, HEAD).await;

    assert_eq!(
        after_down,
        vec![strings(&["false", "false", "false", "true"])]
    );
    assert_eq!(after_up, vec![strings(&["true", "true", "true", "true"])]);
    assert_eq!(head.len(), 1);
}

#[test]
fn the_migration_is_a_reversible_pair() {
    let pair: Vec<bool> = MIGRATOR
        .iter()
        .filter(|migration| migration.version == version())
        .map(|migration| migration.migration_type.is_down_migration())
        .collect();

    assert_eq!(pair.len(), 2);
    assert!(pair.contains(&true));
    assert!(pair.contains(&false));
}
