//! `PgIamUnitOfWork`: one transaction per change under the policy-version row lock, the outbox
//! event rows, the same-transaction audit record, the change receipt and the idempotency record.

use std::time::Duration;

use iam_domain::{
    AuditChainHead, ChangeReceipt, ChangeReceiptRepository as _, ChangeStatement, DecisionEffect,
    EventValue, IamChange, IamUnitOfWork as _, PolicyVersion, RepositoryError,
    SecurityAuditLog as _,
};
use iam_infrastructure::persistence::event_encoding::encode;
use iam_infrastructure::{PgChangeReceiptRepository, PgIamUnitOfWork, PgSecurityAuditLog};
use serde_json::Value;
use shared_infrastructure::persistence::{PostgresSettings, connect_lazy};
use sqlx::postgres::PgPoolOptions;
use sqlx::types::Uuid as SqlUuid;
use sqlx::{PgPool, Row as _};
use test_support::log::LogRecorder;
use test_support::security_audit::security_audit_event;
use test_support::seed::TestRng;
use test_support::unit_of_work::{iam_change, rebuilt};

/// URL that nothing listens on: the "unreachable database" case. No container is stopped.
const DEAD_DATABASE_URL: &str = "postgres://app:unused@127.0.0.1:1/app";

/// The number of rows of each table that a change writes.
#[derive(Debug, PartialEq, Eq)]
struct Counts {
    version: i64,
    outbox: i64,
    audit: i64,
    receipts: i64,
    keys: i64,
}

async fn counts(pool: &PgPool) -> Counts {
    let (version, outbox, audit, receipts, keys): (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT version FROM iam_policy_epoch WHERE id = 1), \
         (SELECT count(*) FROM iam_outbox WHERE kind = 'event'), (SELECT count(*) FROM iam_security_audit_events), \
         (SELECT count(*) FROM iam_change_receipts), (SELECT count(*) FROM iam_idempotency_keys)",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    Counts {
        version,
        outbox,
        audit,
        receipts,
        keys,
    }
}

const EMPTY: Counts = Counts {
    version: 0,
    outbox: 0,
    audit: 0,
    receipts: 0,
    keys: 0,
};

async fn execute(pool: &PgPool, sql: &'static str) {
    sqlx::query(sql).execute(pool).await.unwrap();
}

/// The stored receipt of a change: actor, target type, target id, entity version, policy version.
async fn stored_receipt(
    pool: &PgPool,
    change: &IamChange,
) -> (String, String, String, i64, Option<i64>) {
    sqlx::query_as(
        "SELECT actor, target_type, target_id, entity_version, policy_version \
         FROM iam_change_receipts WHERE change_id = $1",
    )
    .bind(change.parts().change_id.as_uuid().as_uuid())
    .fetch_one(pool)
    .await
    .unwrap()
}

/// The policy version of the audit record of a change.
async fn audit_policy_version(pool: &PgPool, change: &IamChange) -> Option<i64> {
    sqlx::query_scalar("SELECT policy_version FROM iam_security_audit_events WHERE id = $1")
        .bind(change.parts().audit.parts().id.as_uuid().as_uuid())
        .fetch_one(pool)
        .await
        .unwrap()
}

/// The policy versions of the outbox rows of a change, in the order of its events.
async fn outbox_versions(pool: &PgPool, change: &IamChange) -> Vec<i64> {
    let mut versions = Vec::new();
    for envelope in &change.parts().events {
        let version: i64 =
            sqlx::query_scalar("SELECT policy_version FROM iam_outbox WHERE id = $1")
                .bind(envelope.parts().id.as_uuid())
                .fetch_one(pool)
                .await
                .unwrap();
        versions.push(version);
    }
    versions
}

fn policy(value: i64) -> Option<PolicyVersion> {
    PolicyVersion::new(value).ok()
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_change_that_affects_decisions_commits_every_record_under_the_next_version(pool: PgPool) {
    let (recorder, _guard) = LogRecorder::install();
    let change = iam_change(&mut TestRng::from_env(), DecisionEffect::Affected, 2);
    let unit = PgIamUnitOfWork::new(pool.clone());

    let receipt = unit
        .commit(change.clone(), iam_domain::WriteMode::Published)
        .await
        .unwrap();

    let audit = change.parts().audit.parts();
    let record = change.idempotency_record().unwrap();
    assert_eq!(receipt, change.receipt(PolicyVersion::new(1).unwrap()));
    assert_eq!(receipt.policy_version(), policy(1));
    assert_eq!(
        counts(&pool).await,
        Counts {
            version: 1,
            outbox: 2,
            audit: 1,
            receipts: 1,
            keys: 1
        }
    );
    assert_eq!(
        stored_receipt(&pool, &change).await,
        (
            audit.actor.to_string(),
            audit.target.target_type().to_owned(),
            audit.target.target_id().to_owned(),
            change.parts().entity_version.value(),
            Some(1)
        )
    );
    assert_eq!(audit_policy_version(&pool, &change).await, Some(1));
    assert_eq!(outbox_versions(&pool, &change).await, vec![1, 1]);
    let (actor, key, digest, change_id, created_micros): (String, String, Vec<u8>, SqlUuid, i64) =
        sqlx::query_as(
            "SELECT actor, idempotency_key, request_digest, change_id, \
             (extract(epoch FROM created_at) * 1000000)::bigint FROM iam_idempotency_keys",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(actor, record.actor().to_string());
    assert_eq!(key, record.key().as_str());
    assert_eq!(digest, record.request_digest().as_bytes().to_vec());
    assert_eq!(change_id, change.parts().change_id.as_uuid().as_uuid());
    assert_eq!(created_micros, change.occurred_at_micros());
    let audit_lines = recorder
        .lines()
        .into_iter()
        .filter(|line| line.target == "audit")
        .count();
    assert_eq!(audit_lines, 1);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_commit_waits_for_the_policy_version_lock_and_then_shows_everything_at_once(
    pool: PgPool,
) {
    let change = iam_change(&mut TestRng::from_env(), DecisionEffect::RevocationClass, 1);
    let unit = PgIamUnitOfWork::new(pool.clone());
    let mut holder = pool.begin().await.unwrap();
    sqlx::query("SELECT version FROM iam_policy_epoch WHERE id = 1 FOR UPDATE")
        .execute(&mut *holder)
        .await
        .unwrap();

    let pending =
        tokio::spawn(async move { unit.commit(change, iam_domain::WriteMode::Published).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let while_locked = counts(&pool).await;
    let finished_while_locked = pending.is_finished();
    holder.commit().await.unwrap();
    let receipt = pending.await.unwrap().unwrap();

    assert_eq!(while_locked, EMPTY);
    assert!(!finished_while_locked);
    assert_eq!(receipt.policy_version(), policy(1));
    assert_eq!(
        counts(&pool).await,
        Counts {
            version: 1,
            outbox: 1,
            audit: 1,
            receipts: 1,
            keys: 1
        }
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_statement_that_fails_leaves_nothing_visible(pool: PgPool) {
    let (recorder, _guard) = LogRecorder::install();
    let change = rebuilt(
        &iam_change(&mut TestRng::from_env(), DecisionEffect::Affected, 2),
        |parts| {
            parts.statements = vec![ChangeStatement::ExpectPolicyVersion(
                PolicyVersion::new(5).unwrap(),
            )];
        },
    );
    let unit = PgIamUnitOfWork::new(pool.clone());

    let error = unit
        .commit(change, iam_domain::WriteMode::Published)
        .await
        .unwrap_err();

    assert!(matches!(error, RepositoryError::Conflict));
    assert_eq!(counts(&pool).await, EMPTY);
    assert!(recorder.lines().iter().all(|line| line.target != "audit"));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_statement_that_holds_lets_the_change_commit(pool: PgPool) {
    let change = rebuilt(
        &iam_change(&mut TestRng::from_env(), DecisionEffect::Affected, 0),
        |parts| {
            parts.statements = vec![ChangeStatement::ExpectPolicyVersion(
                PolicyVersion::new(0).unwrap(),
            )];
        },
    );
    let unit = PgIamUnitOfWork::new(pool.clone());

    let receipt = unit
        .commit(change, iam_domain::WriteMode::Published)
        .await
        .unwrap();

    assert_eq!(receipt.policy_version(), policy(1));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_failing_last_write_rolls_back_the_version_the_outbox_the_audit_and_the_receipt(
    pool: PgPool,
) {
    let mut rng = TestRng::from_env();
    let first = iam_change(&mut rng, DecisionEffect::Affected, 1);
    let replay = rebuilt(
        &iam_change(&mut rng, DecisionEffect::Affected, 2),
        |parts| {
            let mut audit = first.parts().audit.parts().clone();
            audit.id = parts.audit.parts().id;
            parts.audit = iam_domain::SecurityAuditEvent::record(audit).unwrap();
            parts.idempotency = first.parts().idempotency.clone();
        },
    );
    let unit = PgIamUnitOfWork::new(pool.clone());
    unit.commit(first.clone(), iam_domain::WriteMode::Published)
        .await
        .unwrap();
    let before = counts(&pool).await;
    let head = PgSecurityAuditLog::new(pool.clone())
        .chain_head()
        .await
        .unwrap();

    let error = unit
        .commit(replay.clone(), iam_domain::WriteMode::Published)
        .await
        .unwrap_err();

    assert!(matches!(error, RepositoryError::AlreadyExists));
    assert_eq!(
        before,
        Counts {
            version: 1,
            outbox: 1,
            audit: 1,
            receipts: 1,
            keys: 1
        }
    );
    assert_eq!(counts(&pool).await, before);
    assert_eq!(
        PgSecurityAuditLog::new(pool.clone())
            .chain_head()
            .await
            .unwrap(),
        head
    );
    let replayed_events: i64 =
        sqlx::query_scalar("SELECT count(*) FROM iam_outbox WHERE id = ANY($1)")
            .bind(
                replay
                    .parts()
                    .events
                    .iter()
                    .map(|envelope| envelope.parts().id.as_uuid())
                    .collect::<Vec<_>>(),
            )
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(replayed_events, 0);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_reused_change_id_or_event_id_is_a_duplicate_and_commits_nothing(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let first = iam_change(&mut rng, DecisionEffect::Affected, 1);
    let same_change = rebuilt(
        &iam_change(&mut rng, DecisionEffect::Affected, 0),
        |parts| {
            parts.change_id = first.parts().change_id;
        },
    );
    let same_event = rebuilt(
        &iam_change(&mut rng, DecisionEffect::Affected, 0),
        |parts| {
            parts.events = first.parts().events.clone();
        },
    );
    let unit = PgIamUnitOfWork::new(pool.clone());
    unit.commit(first, iam_domain::WriteMode::Published)
        .await
        .unwrap();
    let before = counts(&pool).await;

    let by_change = unit
        .commit(same_change, iam_domain::WriteMode::Published)
        .await
        .unwrap_err();
    let by_event = unit
        .commit(same_event, iam_domain::WriteMode::Published)
        .await
        .unwrap_err();

    assert!(matches!(by_change, RepositoryError::AlreadyExists));
    assert!(matches!(by_event, RepositoryError::AlreadyExists));
    assert_eq!(counts(&pool).await, before);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_event_larger_than_64_kib_is_unavailable_and_commits_nothing(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let change = rebuilt(
        &iam_change(&mut rng, DecisionEffect::Affected, 1),
        |parts| {
            let envelope = parts.events[0].parts().clone();
            let data = envelope
                .data
                .clone()
                .with("padding", EventValue::Text("a".repeat(65_536)))
                .unwrap();
            parts.events = vec![
                iam_domain::EventEnvelope::new(iam_domain::EventEnvelopeParts { data, ..envelope })
                    .unwrap(),
            ];
        },
    );
    let unit = PgIamUnitOfWork::new(pool.clone());

    let error = unit
        .commit(change, iam_domain::WriteMode::Published)
        .await
        .unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
    assert_eq!(
        std::error::Error::source(&error).unwrap().to_string(),
        "The encoded event must be at most 65536 bytes."
    );
    assert_eq!(counts(&pool).await, EMPTY);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_hundred_changes_from_four_connections_take_consecutive_versions(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let batches: Vec<Vec<IamChange>> = (0..4)
        .map(|_batch| {
            (0..25)
                .map(|_index| iam_change(&mut rng, DecisionEffect::Affected, 2))
                .collect()
        })
        .collect();
    let options = (*pool.connect_options()).clone();
    let mut tasks = Vec::new();
    for batch in batches.clone() {
        let connection = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy_with(options.clone());
        let unit = PgIamUnitOfWork::new(connection);
        tasks.push(tokio::spawn(async move {
            let mut receipts = Vec::new();
            for change in batch {
                receipts.push(
                    unit.commit(change, iam_domain::WriteMode::Published)
                        .await
                        .unwrap(),
                );
            }
            receipts
        }));
    }
    let mut receipts: Vec<ChangeReceipt> = Vec::new();
    for task in tasks {
        receipts.extend(task.await.unwrap());
    }

    let mut versions: Vec<i64> = receipts
        .iter()
        .map(|receipt| receipt.policy_version().unwrap().value())
        .collect();
    versions.sort_unstable();
    assert_eq!(versions, (1..=100).collect::<Vec<i64>>());
    let changes: Vec<&IamChange> = batches.iter().flatten().collect();
    for change in &changes {
        let receipt = receipts
            .iter()
            .find(|receipt| receipt.change_id() == change.parts().change_id)
            .unwrap();
        let version = receipt.policy_version().unwrap().value();
        assert_eq!(outbox_versions(&pool, change).await, vec![version, version]);
        assert_eq!(audit_policy_version(&pool, change).await, Some(version));
        assert_eq!(stored_receipt(&pool, change).await.4, Some(version));
    }
    let by_position: Vec<i64> = sqlx::query_scalar(
        "SELECT policy_version FROM iam_outbox WHERE kind = 'event' ORDER BY position",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(by_position.len(), 200);
    assert!(by_position.windows(2).all(|pair| pair[0] <= pair[1]));
    assert_eq!(
        counts(&pool).await,
        Counts {
            version: 100,
            outbox: 200,
            audit: 100,
            receipts: 100,
            keys: 100
        }
    );
    let records = PgSecurityAuditLog::new(pool.clone())
        .find_after(0, 1_000)
        .await
        .unwrap();
    let seqs: Vec<i64> = records
        .iter()
        .map(iam_domain::StoredSecurityAuditEvent::seq)
        .collect();
    assert_eq!(seqs, (1..=100).collect::<Vec<i64>>());
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_change_that_does_not_affect_decisions_keeps_the_version_and_has_no_policy_version(
    pool: PgPool,
) {
    let mut rng = TestRng::from_env();
    let affecting = iam_change(&mut rng, DecisionEffect::Affected, 0);
    let neutral = iam_change(&mut rng, DecisionEffect::Unaffected, 1);
    let unit = PgIamUnitOfWork::new(pool.clone());
    unit.commit(affecting, iam_domain::WriteMode::Published)
        .await
        .unwrap();

    let receipt = unit
        .commit(neutral.clone(), iam_domain::WriteMode::Published)
        .await
        .unwrap();

    assert_eq!(receipt.policy_version(), None);
    assert_eq!(counts(&pool).await.version, 1);
    assert_eq!(stored_receipt(&pool, &neutral).await.4, None);
    assert_eq!(audit_policy_version(&pool, &neutral).await, None);
    assert_eq!(outbox_versions(&pool, &neutral).await, vec![1]);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_change_without_an_idempotency_key_writes_no_idempotency_record(pool: PgPool) {
    let change = rebuilt(
        &iam_change(&mut TestRng::from_env(), DecisionEffect::Affected, 0),
        |parts| parts.idempotency = None,
    );
    let unit = PgIamUnitOfWork::new(pool.clone());

    unit.commit(change, iam_domain::WriteMode::Published)
        .await
        .unwrap();

    let after = counts(&pool).await;
    assert_eq!((after.receipts, after.keys), (1, 0));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_committed_event_row_is_an_unpublished_envelope_keyed_by_its_aggregate(pool: PgPool) {
    let change = iam_change(&mut TestRng::from_env(), DecisionEffect::Affected, 1);
    let envelope = change.parts().events[0].clone();
    let unit = PgIamUnitOfWork::new(pool.clone());

    unit.commit(change, iam_domain::WriteMode::Published)
        .await
        .unwrap();

    let row = sqlx::query(
        "SELECT kind, topic, record_key, payload, policy_version, seq, count, digest_after, \
         log_epoch, event_type, aggregate_id, \
         (extract(epoch FROM occurred_at) * 1000000)::bigint AS occurred_at_micros, \
         published_at IS NULL AS unpublished, published_offset, relay_epoch \
         FROM iam_outbox WHERE id = $1",
    )
    .bind(envelope.parts().id.as_uuid())
    .fetch_one(&pool)
    .await
    .unwrap();
    let aggregate = envelope.parts().aggregate_id.to_string();
    let payload: String = row.get("payload");
    assert_eq!(row.get::<String, _>("kind"), "event");
    assert_eq!(row.get::<String, _>("topic"), "iam.events.v1");
    assert_eq!(row.get::<String, _>("record_key"), aggregate);
    assert_eq!(
        payload,
        encode(&envelope, PolicyVersion::new(1).unwrap()).unwrap()
    );
    assert_eq!(row.get::<i64, _>("policy_version"), 1);
    assert_eq!(row.get::<Option<i32>, _>("seq"), None);
    assert_eq!(row.get::<Option<i32>, _>("count"), None);
    assert_eq!(row.get::<Option<Vec<u8>>, _>("digest_after"), None);
    assert_eq!(row.get::<i64, _>("log_epoch"), 0);
    assert_eq!(
        row.get::<Option<String>, _>("event_type").as_deref(),
        Some("iam.role.updated")
    );
    assert_eq!(
        row.get::<Option<String>, _>("aggregate_id").as_deref(),
        Some(aggregate.as_str())
    );
    assert_eq!(
        row.get::<i64, _>("occurred_at_micros"),
        envelope.occurred_at_micros()
    );
    assert!(row.get::<bool, _>("unpublished"));
    assert_eq!(row.get::<Option<i64>, _>("published_offset"), None);
    assert_eq!(row.get::<Option<i64>, _>("relay_epoch"), None);
    let decoded: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(
        decoded["id"],
        Value::String(envelope.parts().id.to_string())
    );
    assert_eq!(decoded["data"]["aggregateId"], Value::String(aggregate));
    assert_eq!(decoded["data"]["policyVersion"], Value::from(1));
    assert!(payload.len() <= 65_536);
    assert!(!payload.contains("eyJ"));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_partial_index_covers_unpublished_event_rows_only(pool: PgPool) {
    let change = iam_change(&mut TestRng::from_env(), DecisionEffect::Affected, 2);
    let published = change.parts().events[1].parts().id.as_uuid();
    let unit = PgIamUnitOfWork::new(pool.clone());
    unit.commit(change.clone(), iam_domain::WriteMode::Published)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE iam_outbox SET published_at = now(), published_offset = 7, relay_epoch = 0 \
         WHERE id = $1",
    )
    .bind(published)
    .execute(&pool)
    .await
    .unwrap();

    let predicate: String = sqlx::query_scalar(
        "SELECT pg_get_expr(indpred, indrelid) FROM pg_index \
         WHERE indexrelid = 'iam_outbox_unpublished_idx'::regclass",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let mut connection = pool.acquire().await.unwrap();
    sqlx::query("SET enable_seqscan = off")
        .execute(&mut *connection)
        .await
        .unwrap();
    let plan: Vec<String> = sqlx::query_scalar(
        "EXPLAIN SELECT id FROM iam_outbox WHERE published_at IS NULL ORDER BY position",
    )
    .fetch_all(&mut *connection)
    .await
    .unwrap();
    let unpublished: Vec<SqlUuid> = sqlx::query_scalar(
        "SELECT id FROM iam_outbox WHERE published_at IS NULL AND kind = 'event' ORDER BY position",
    )
    .fetch_all(&mut *connection)
    .await
    .unwrap();

    assert_eq!(predicate, "(published_at IS NULL)");
    assert!(
        plan.iter()
            .any(|line| line.contains("iam_outbox_unpublished_idx")),
        "{plan:?}"
    );
    assert_eq!(
        unpublished,
        vec![change.parts().events[0].parts().id.as_uuid()]
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_missing_or_unusable_policy_epoch_row_is_unavailable(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let unit = PgIamUnitOfWork::new(pool.clone());
    execute(
        &pool,
        "ALTER TABLE iam_policy_epoch DROP CONSTRAINT iam_policy_epoch_version_check",
    )
    .await;
    execute(&pool, "UPDATE iam_policy_epoch SET version = -1").await;
    let unusable = unit
        .commit(
            iam_change(&mut rng, DecisionEffect::Unaffected, 0),
            iam_domain::WriteMode::Published,
        )
        .await
        .unwrap_err();
    execute(&pool, "UPDATE iam_policy_epoch SET version = -2").await;
    let incremented = unit
        .commit(
            iam_change(&mut rng, DecisionEffect::Affected, 0),
            iam_domain::WriteMode::Published,
        )
        .await
        .unwrap_err();
    execute(&pool, "DELETE FROM iam_policy_epoch").await;
    let missing = unit
        .commit(
            iam_change(&mut rng, DecisionEffect::Affected, 0),
            iam_domain::WriteMode::Published,
        )
        .await
        .unwrap_err();

    assert!(matches!(unusable, RepositoryError::Unavailable(_)));
    assert!(matches!(incremented, RepositoryError::Unavailable(_)));
    assert!(matches!(missing, RepositoryError::Unavailable(_)));
    let after = counts_without_epoch(&pool).await;
    assert_eq!(after, (0, 0, 0, 0));
    assert_eq!(
        PgSecurityAuditLog::new(pool).chain_head().await.unwrap(),
        AuditChainHead::GENESIS
    );
}

async fn counts_without_epoch(pool: &PgPool) -> (i64, i64, i64, i64) {
    sqlx::query_as(
        "SELECT (SELECT count(*) FROM iam_outbox WHERE kind = 'event'), (SELECT count(*) FROM iam_security_audit_events), \
         (SELECT count(*) FROM iam_change_receipts), (SELECT count(*) FROM iam_idempotency_keys)",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn an_unreachable_database_is_unavailable() {
    let change = iam_change(&mut TestRng::from_env(), DecisionEffect::Affected, 1);
    let pool = connect_lazy(&PostgresSettings {
        url: DEAD_DATABASE_URL.to_owned(),
        max_connections: 1,
        acquire_timeout: Duration::from_millis(500),
        statement_timeout: Duration::from_secs(1),
    })
    .unwrap();
    let unit = PgIamUnitOfWork::new(pool);

    let error = unit
        .commit(change, iam_domain::WriteMode::Published)
        .await
        .unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_change_that_revokes_assignments_stores_their_number_and_every_audit_record(
    pool: PgPool,
) {
    let mut rng = TestRng::from_env();
    let change = iam_change(&mut rng, DecisionEffect::Affected, 3)
        .with_revoked_assignments(2)
        .with_related_audits(vec![
            security_audit_event(&mut rng),
            security_audit_event(&mut rng),
        ])
        .unwrap();
    let unit = PgIamUnitOfWork::new(pool.clone());

    let receipt = unit
        .commit(change.clone(), iam_domain::WriteMode::Published)
        .await
        .unwrap();

    assert_eq!(receipt.revoked_assignments(), Some(2));
    assert_eq!(counts(&pool).await.audit, 3);
    let stored: Option<i32> = sqlx::query_scalar(
        "SELECT revoked_assignments FROM iam_change_receipts WHERE change_id = $1",
    )
    .bind(change.parts().change_id.as_uuid().as_uuid())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored, Some(2));
    let read = PgChangeReceiptRepository::new(pool.clone())
        .find(change.parts().change_id)
        .await
        .unwrap();
    assert_eq!(read, receipt);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_change_that_revokes_no_assignments_stores_no_number(pool: PgPool) {
    let change = iam_change(&mut TestRng::from_env(), DecisionEffect::Affected, 1);
    let unit = PgIamUnitOfWork::new(pool.clone());

    unit.commit(change.clone(), iam_domain::WriteMode::Published)
        .await
        .unwrap();

    let stored: Option<i32> = sqlx::query_scalar(
        "SELECT revoked_assignments FROM iam_change_receipts WHERE change_id = $1",
    )
    .bind(change.parts().change_id.as_uuid().as_uuid())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored, None);
    let read = PgChangeReceiptRepository::new(pool)
        .find(change.parts().change_id)
        .await
        .unwrap();
    assert_eq!(read.revoked_assignments(), None);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn event_rows_name_the_events_topic_of_the_unit_of_work(pool: PgPool) {
    let change = iam_change(&mut TestRng::from_env(), DecisionEffect::Affected, 2);
    let unit =
        PgIamUnitOfWork::new(pool.clone()).with_events_topic("iam.events.scenario".to_owned());

    unit.commit(change.clone(), iam_domain::WriteMode::Published)
        .await
        .unwrap();

    for envelope in &change.parts().events {
        let topic: String = sqlx::query_scalar("SELECT topic FROM iam_outbox WHERE id = $1")
            .bind(envelope.parts().id.as_uuid())
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(topic, "iam.events.scenario");
    }
}
