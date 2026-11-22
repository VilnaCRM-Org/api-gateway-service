//! The migration `create_iam_policy_epoch`: the table, its named constraints, the seeded row and
//! the down migration.

use shared_infrastructure::persistence::MIGRATOR;
use sqlx::{PgPool, Row as _};

const COLUMNS: &str = "SELECT column_name::text, data_type::text, is_nullable::text, \
    ordinal_position::text FROM information_schema.columns \
    WHERE table_schema = current_schema() AND table_name = 'iam_policy_epoch' \
    ORDER BY ordinal_position";

const CONSTRAINTS: &str = "SELECT conname::text, contype::text, pg_get_constraintdef(oid) \
    FROM pg_constraint WHERE conrelid = 'iam_policy_epoch'::regclass ORDER BY conname";

const TABLE_EXISTS: &str = "SELECT to_regclass('iam_policy_epoch') IS NOT NULL";

const EXAMPLE_TABLE_EXISTS: &str = "SELECT to_regclass('example_api_resources') IS NOT NULL";

const SEEDED: &str = "SELECT id::text, version::text, encode(digest, 'hex'), log_epoch::text, \
    relay_epoch::text, catalog_epoch::text, (updated_at <= now())::text FROM iam_policy_epoch";

const INSERT: &str = "INSERT INTO iam_policy_epoch \
    (id, version, digest, log_epoch, relay_epoch, catalog_epoch, updated_at) \
    VALUES ($1, $2, $3, $4, $5, $6, now())";

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

async fn exists(pool: &PgPool, sql: &'static str) -> bool {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

/// The version of the migration that creates the table.
fn version() -> i64 {
    MIGRATOR
        .iter()
        .find(|migration| migration.description.contains("create iam policy epoch"))
        .unwrap()
        .version
}

/// Tries to store a row with the given values next to what the table holds.
async fn insert(
    pool: &PgPool,
    id: i16,
    numbers: [i64; 4],
    digest: &[u8],
) -> Result<(), sqlx::Error> {
    let [version, log_epoch, relay_epoch, catalog_epoch] = numbers;
    sqlx::query(INSERT)
        .bind(id)
        .bind(version)
        .bind(digest)
        .bind(log_epoch)
        .bind(relay_epoch)
        .bind(catalog_epoch)
        .execute(pool)
        .await
        .map(|_done| ())
}

/// Removes the seeded row, so that the next insert is judged by the constraints alone.
async fn clear(pool: &PgPool) {
    sqlx::query("DELETE FROM iam_policy_epoch")
        .execute(pool)
        .await
        .unwrap();
}

/// Tries to store a row with the given values in the emptied table.
async fn replace(
    pool: &PgPool,
    id: i16,
    numbers: [i64; 4],
    digest: &[u8],
) -> Result<(), sqlx::Error> {
    clear(pool).await;
    insert(pool, id, numbers, digest).await
}

#[sqlx::test(migrations = false)]
async fn the_migration_creates_the_table_with_named_constraints(pool: PgPool) {
    MIGRATOR.run(&pool).await.unwrap();

    let columns = rows(&pool, COLUMNS).await;
    let constraints = rows(&pool, CONSTRAINTS).await;

    assert_eq!(
        columns,
        vec![
            strings(&["id", "smallint", "NO", "1"]),
            strings(&["version", "bigint", "NO", "2"]),
            strings(&["digest", "bytea", "NO", "3"]),
            strings(&["log_epoch", "bigint", "NO", "4"]),
            strings(&["relay_epoch", "bigint", "NO", "5"]),
            strings(&["catalog_epoch", "bigint", "NO", "6"]),
            strings(&["updated_at", "timestamp with time zone", "NO", "7"]),
        ]
    );
    assert_eq!(
        constraints,
        vec![
            strings(&[
                "iam_policy_epoch_catalog_epoch_check",
                "c",
                "CHECK ((catalog_epoch >= 0))"
            ]),
            strings(&[
                "iam_policy_epoch_digest_check",
                "c",
                "CHECK ((octet_length(digest) = 16))"
            ]),
            strings(&["iam_policy_epoch_id_check", "c", "CHECK ((id = 1))"]),
            strings(&[
                "iam_policy_epoch_log_epoch_check",
                "c",
                "CHECK ((log_epoch >= 0))"
            ]),
            strings(&["iam_policy_epoch_pkey", "p", "PRIMARY KEY (id)"]),
            strings(&[
                "iam_policy_epoch_relay_epoch_check",
                "c",
                "CHECK ((relay_epoch >= 0))"
            ]),
            strings(&[
                "iam_policy_epoch_version_check",
                "c",
                "CHECK ((version >= 0))"
            ]),
        ]
    );
}

#[sqlx::test(migrations = false)]
async fn the_migration_seeds_one_row_of_zeros(pool: PgPool) {
    MIGRATOR.run(&pool).await.unwrap();

    let seeded = rows(&pool, SEEDED).await;

    assert_eq!(
        seeded,
        vec![strings(&[
            "1",
            "0",
            "00000000000000000000000000000000",
            "0",
            "0",
            "0",
            "true"
        ])]
    );
}

#[sqlx::test(migrations = false)]
async fn the_table_holds_exactly_the_row_with_id_1(pool: PgPool) {
    MIGRATOR.run(&pool).await.unwrap();

    let second_row = insert(&pool, 2, [0; 4], &[0; 16]).await;
    let duplicate = insert(&pool, 1, [0; 4], &[0; 16]).await;
    let other_id = replace(&pool, 2, [0; 4], &[0; 16]).await;
    let replaced = replace(&pool, 1, [1, 2, 3, 4], &[9; 16]).await;

    assert!(second_row.is_err());
    assert!(duplicate.is_err());
    assert!(other_id.is_err());
    assert!(replaced.is_ok());
}

#[sqlx::test(migrations = false)]
async fn the_constraints_reject_a_digest_of_another_length_and_negative_numbers(pool: PgPool) {
    MIGRATOR.run(&pool).await.unwrap();

    let short_digest = replace(&pool, 1, [0; 4], &[0; 15]).await;
    let long_digest = replace(&pool, 1, [0; 4], &[0; 17]).await;
    let negative_version = replace(&pool, 1, [-1, 0, 0, 0], &[0; 16]).await;
    let negative_log_epoch = replace(&pool, 1, [0, -1, 0, 0], &[0; 16]).await;
    let negative_relay_epoch = replace(&pool, 1, [0, 0, -1, 0], &[0; 16]).await;
    let negative_catalog_epoch = replace(&pool, 1, [0, 0, 0, -1], &[0; 16]).await;
    let largest = replace(&pool, 1, [i64::MAX; 4], &[255; 16]).await;

    assert!(short_digest.is_err());
    assert!(long_digest.is_err());
    assert!(negative_version.is_err());
    assert!(negative_log_epoch.is_err());
    assert!(negative_relay_epoch.is_err());
    assert!(negative_catalog_epoch.is_err());
    assert!(largest.is_ok());
}

#[sqlx::test(migrations = false)]
async fn the_down_migration_drops_the_table_only_and_the_up_migration_seeds_it_again(pool: PgPool) {
    MIGRATOR.run(&pool).await.unwrap();
    sqlx::query("UPDATE iam_policy_epoch SET version = 9")
        .execute(&pool)
        .await
        .unwrap();

    MIGRATOR
        .undo(&pool, version().saturating_sub(1))
        .await
        .unwrap();
    let table_after_down = exists(&pool, TABLE_EXISTS).await;
    let example_table_after_down = exists(&pool, EXAMPLE_TABLE_EXISTS).await;
    MIGRATOR.run(&pool).await.unwrap();
    let seeded = rows(&pool, SEEDED).await;

    assert!(!table_after_down);
    assert!(example_table_after_down);
    assert_eq!(seeded.len(), 1);
    assert_eq!(seeded[0][1], "0");
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
