//! `PgSecurityAuditLog`: the hash chain computed in SQL under the chain-head lock, the append-only
//! trigger, concurrent appends, the `audit` tracing event and the reads.

use std::time::Duration;

use iam_domain::{
    AuditAction, AuditChainHead, AuditHash, AuditOutcome, AuditSummary, RepositoryError,
    SecurityAuditEvent, SecurityAuditFilter, SecurityAuditLog as _, SecurityAuditSearch,
    StoredSecurityAuditEvent,
};
use iam_infrastructure::PgSecurityAuditLog;
use shared_infrastructure::persistence::{PostgresSettings, connect_lazy};
use sqlx::PgPool;
use test_support::log::LogRecorder;
use test_support::security_audit::security_audit_event;
use test_support::seed::TestRng;

/// URL that nothing listens on: the "unreachable database" case. No container is stopped.
const DEAD_DATABASE_URL: &str = "postgres://app:unused@127.0.0.1:1/app";

/// A token and a specification body that must never reach the row or the event.
const TOKEN: &str = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl";
const SPECIFICATION: &str = "openapi: 3.1.0\ninfo:\n  title: core";

fn events(rng: &mut TestRng, count: usize) -> Vec<SecurityAuditEvent> {
    (0..count).map(|_index| security_audit_event(rng)).collect()
}

async fn all_records(log: &PgSecurityAuditLog) -> Vec<StoredSecurityAuditEvent> {
    log.find_after(0, 10_000).await.unwrap()
}

async fn execute(pool: &PgPool, sql: &'static str) -> Result<u64, sqlx::Error> {
    sqlx::query(sql)
        .execute(pool)
        .await
        .map(|done| done.rows_affected())
}

/// The digest PostgreSQL computes for a link: `sha256(prev_hash || canonical_form)`.
async fn sql_digest(pool: &PgPool, prev_hash: AuditHash, canonical_form: &str) -> Vec<u8> {
    sqlx::query_scalar("SELECT sha256($1 || convert_to($2, 'UTF8'))")
        .bind(prev_hash.as_bytes().as_slice())
        .bind(canonical_form)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Checks that the records form one gap-free chain from the genesis hash and returns its head.
async fn verify_chain(pool: &PgPool, records: &[StoredSecurityAuditEvent]) -> AuditChainHead {
    let mut head = AuditChainHead::GENESIS;
    for record in records {
        let expected = head.seq().checked_add(1).unwrap();
        assert_eq!(record.seq(), expected, "gap before {}", record.seq());
        assert_eq!(record.prev_hash(), head.hash(), "seq {}", record.seq());
        let digest = sql_digest(pool, record.prev_hash(), &record.event().canonical_form()).await;
        assert_eq!(
            record.hash().as_bytes().as_slice(),
            digest.as_slice(),
            "seq {}",
            record.seq()
        );
        head = AuditChainHead::new(record.seq(), record.hash()).unwrap();
    }
    head
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn records_appended_in_sequence_form_a_chain_digested_in_sql(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let first = security_audit_event(&mut rng);
    let batch = events(&mut rng, 2);
    let log = PgSecurityAuditLog::new(pool.clone());

    let after_first = log
        .append_batch(std::slice::from_ref(&first))
        .await
        .unwrap();
    let after_batch = log.append_batch(&batch).await.unwrap();

    let records = all_records(&log).await;
    let verified = verify_chain(&pool, &records).await;
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].event(), &first);
    assert_eq!(records[1].event(), &batch[0]);
    assert_eq!(records[2].event(), &batch[1]);
    assert_eq!(records[0].prev_hash(), AuditHash::GENESIS);
    assert_eq!(records[1].prev_hash(), records[0].hash());
    assert_eq!(records[2].prev_hash(), records[1].hash());
    assert_eq!(after_first.seq(), 1);
    assert_eq!(after_first.hash(), records[0].hash());
    assert_eq!(after_batch, verified);
    assert_eq!(log.chain_head().await.unwrap(), verified);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_trigger_rejects_update_delete_and_truncate_and_the_row_is_unchanged(pool: PgPool) {
    let event = security_audit_event(&mut TestRng::from_env());
    let log = PgSecurityAuditLog::new(pool.clone());
    log.append_batch(std::slice::from_ref(&event))
        .await
        .unwrap();
    let before = log.find_by_id(event.parts().id).await.unwrap();

    let update = execute(
        &pool,
        "UPDATE iam_security_audit_events SET actor = 'system:startup'",
    )
    .await
    .unwrap_err();
    let delete = execute(&pool, "DELETE FROM iam_security_audit_events")
        .await
        .unwrap_err();
    let truncate = execute(&pool, "TRUNCATE iam_security_audit_events")
        .await
        .unwrap_err();

    for (error, operation) in [
        (update, "UPDATE"),
        (delete, "DELETE"),
        (truncate, "TRUNCATE"),
    ] {
        let message = error.as_database_error().unwrap().message().to_owned();
        assert_eq!(
            message,
            format!("iam_security_audit_events is append-only: {operation} is not allowed")
        );
    }
    assert_eq!(log.find_by_id(event.parts().id).await.unwrap(), before);
    assert_eq!(all_records(&log).await.len(), 1);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn concurrent_appends_from_two_connections_leave_no_gap_and_one_chain(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let left_events = events(&mut rng, 20);
    let right_events = events(&mut rng, 20);
    let left = PgSecurityAuditLog::new(pool.clone());
    let right = PgSecurityAuditLog::new(pool.clone());

    let write = async |log: &PgSecurityAuditLog, events: &[SecurityAuditEvent]| {
        for pair in events.chunks(2) {
            log.append_batch(pair).await.unwrap();
        }
    };
    tokio::join!(write(&left, &left_events), write(&right, &right_events));

    let records = all_records(&left).await;
    let head = verify_chain(&pool, &records).await;
    let (count, highest): (i64, i64) =
        sqlx::query_as("SELECT count(*), max(seq) FROM iam_security_audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(records.len(), 40);
    assert_eq!((count, highest), (40, 40));
    assert_eq!(left.chain_head().await.unwrap(), head);
    assert_eq!(head.seq(), 40);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_appended_record_is_one_audit_event_without_a_token_or_a_specification(pool: PgPool) {
    let (recorder, _guard) = LogRecorder::install();
    let event = security_audit_event(&mut TestRng::from_env());
    let log = PgSecurityAuditLog::new(pool.clone());

    let head = log
        .append_batch(std::slice::from_ref(&event))
        .await
        .unwrap();

    let audit: Vec<_> = recorder
        .lines()
        .into_iter()
        .filter(|line| line.target == "audit")
        .collect();
    assert_eq!(audit.len(), 1);
    let line = &audit[0];
    let parts = event.parts();
    assert_eq!(line.level, tracing::Level::INFO);
    assert_eq!(
        line.field("event_name"),
        Some("iam.security_audit.recorded")
    );
    assert_eq!(line.field("seq"), Some("1"));
    assert_eq!(line.field("id"), Some(parts.id.to_string().as_str()));
    let before = parts.before.as_ref().map(AuditSummary::as_str);
    let after = parts.after.as_ref().map(AuditSummary::as_str);
    assert_eq!(line.field("before_summary"), before);
    assert_eq!(line.field("after_summary"), after);
    assert_eq!(line.field("hash"), Some(head.hash().to_string().as_str()));
    let logged = format!("{line:?}");
    let stored: String = sqlx::query_scalar(
        "SELECT concat_ws('|', actor, caller_service, action, target_type, target_id, scope, \
         before_summary, after_summary, idempotency_key, outcome, reason, request_id) \
         FROM iam_security_audit_events",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    for text in [logged, stored] {
        assert!(!text.contains("eyJ"), "{text}");
        assert!(!text.contains(TOKEN), "{text}");
        assert!(!text.contains("openapi"), "{text}");
    }
    assert!(AuditSummary::new(&format!("token={TOKEN}")).is_err());
    assert!(AuditSummary::new(SPECIFICATION).is_err());
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn records_inside_a_rolled_back_transaction_leave_no_trace(pool: PgPool) {
    let (recorder, _guard) = LogRecorder::install();
    let events = events(&mut TestRng::from_env(), 2);
    let log = PgSecurityAuditLog::new(pool.clone());
    let mut transaction = pool.begin().await.unwrap();

    let stored = PgSecurityAuditLog::append_within(&mut transaction, &events)
        .await
        .unwrap();
    transaction.rollback().await.unwrap();

    assert_eq!(stored.len(), 2);
    assert_eq!(stored[1].prev_hash(), stored[0].hash());
    assert_eq!(all_records(&log).await.len(), 0);
    assert_eq!(log.chain_head().await.unwrap(), AuditChainHead::GENESIS);
    assert!(recorder.lines().iter().all(|line| line.target != "audit"));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_empty_batch_writes_nothing_and_returns_the_current_head(pool: PgPool) {
    let event = security_audit_event(&mut TestRng::from_env());
    let log = PgSecurityAuditLog::new(pool);
    let head = log
        .append_batch(std::slice::from_ref(&event))
        .await
        .unwrap();

    let unchanged = log.append_batch(&[]).await.unwrap();

    assert_eq!(unchanged, head);
    assert_eq!(all_records(&log).await.len(), 1);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_batch_with_a_stored_id_is_a_duplicate_and_appends_nothing(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let first = security_audit_event(&mut rng);
    let fresh = security_audit_event(&mut rng);
    let log = PgSecurityAuditLog::new(pool);
    let head = log
        .append_batch(std::slice::from_ref(&first))
        .await
        .unwrap();

    let error = log.append_batch(&[fresh, first]).await.unwrap_err();

    assert!(matches!(error, RepositoryError::AlreadyExists));
    assert_eq!(log.chain_head().await.unwrap(), head);
    assert_eq!(all_records(&log).await.len(), 1);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn records_are_found_by_id_and_paged_by_sequence_number(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let batch = events(&mut rng, 3);
    let unknown = security_audit_event(&mut rng);
    let log = PgSecurityAuditLog::new(pool);
    log.append_batch(&batch).await.unwrap();

    let found = log.find_by_id(batch[1].parts().id).await.unwrap();
    let page = log.find_after(1, 1).await.unwrap();
    let rest = log.find_after(1, 10).await.unwrap();
    let missing = log.find_by_id(unknown.parts().id).await.unwrap_err();

    assert_eq!(found.seq(), 2);
    assert_eq!(found.event(), &batch[1]);
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].seq(), 2);
    assert_eq!(
        rest.iter()
            .map(StoredSecurityAuditEvent::seq)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert!(matches!(missing, RepositoryError::NotFound));
}

fn search(filter: SecurityAuditFilter, before_seq: Option<i64>, limit: u32) -> SecurityAuditSearch {
    SecurityAuditSearch {
        filter,
        before_seq,
        limit,
    }
}

fn seqs(records: &[StoredSecurityAuditEvent]) -> Vec<i64> {
    records.iter().map(StoredSecurityAuditEvent::seq).collect()
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_search_pages_newest_first_and_applies_every_condition(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let batch = events(&mut rng, 4);
    let log = PgSecurityAuditLog::new(pool);
    log.append_batch(&batch).await.unwrap();
    let second = batch[1].parts();
    let micros = batch[1].occurred_at_micros();

    let first_page = log
        .search(&search(SecurityAuditFilter::new(), None, 3))
        .await
        .unwrap();
    let second_page = log
        .search(&search(SecurityAuditFilter::new(), Some(2), 3))
        .await
        .unwrap();
    let by_actor = log
        .search(&search(
            SecurityAuditFilter::new().by_actor(second.actor.clone()),
            None,
            10,
        ))
        .await
        .unwrap();
    let in_range = SecurityAuditFilter::new()
        .within(
            Some(second.occurred_at),
            second.occurred_at.checked_add(Duration::from_micros(1)),
        )
        .unwrap();
    let by_time = log.search(&search(in_range, None, 10)).await.unwrap();
    let about_it = SecurityAuditFilter::new()
        .about(second.target.target_type(), Some(second.target.target_id()))
        .unwrap();
    let by_target = log.search(&search(about_it, None, 10)).await.unwrap();
    let no_match = SecurityAuditFilter::new()
        .of_action(AuditAction::new("role.update").unwrap())
        .with_outcome(AuditOutcome::Rejected);
    let none = log.search(&search(no_match, None, 10)).await.unwrap();
    let all_of_it = SecurityAuditFilter::new()
        .of_action(second.action.clone())
        .with_outcome(AuditOutcome::Committed)
        .about(second.target.target_type(), None)
        .unwrap();
    let every = log.search(&search(all_of_it, None, 10)).await.unwrap();

    assert_eq!(seqs(&first_page), [4, 3, 2]);
    assert_eq!(first_page[0].event(), &batch[3]);
    assert_eq!(seqs(&second_page), [1]);
    assert_eq!(seqs(&by_actor), [2]);
    assert_eq!(
        by_time
            .iter()
            .map(|record| record.event().occurred_at_micros())
            .collect::<Vec<_>>(),
        [micros]
    );
    assert_eq!(seqs(&by_target), [2]);
    assert_eq!(seqs(&none), Vec::<i64>::new());
    assert_eq!(seqs(&every), [4, 3, 2, 1]);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_stored_record_that_breaks_an_invariant_is_unavailable(pool: PgPool) {
    let event = security_audit_event(&mut TestRng::from_env());
    let log = PgSecurityAuditLog::new(pool.clone());
    log.append_batch(std::slice::from_ref(&event))
        .await
        .unwrap();
    execute(
        &pool,
        "ALTER TABLE iam_security_audit_events DISABLE TRIGGER iam_security_audit_events_append_only",
    )
    .await
    .unwrap();
    execute(
        &pool,
        "UPDATE iam_security_audit_events SET actor = 'nobody'",
    )
    .await
    .unwrap();

    let by_id = log.find_by_id(event.parts().id).await.unwrap_err();
    let page = log.find_after(0, 10).await.unwrap_err();

    assert!(matches!(by_id, RepositoryError::Unavailable(_)));
    assert!(matches!(page, RepositoryError::Unavailable(_)));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_chain_head_that_breaks_an_invariant_is_unavailable(pool: PgPool) {
    let event = security_audit_event(&mut TestRng::from_env());
    let log = PgSecurityAuditLog::new(pool.clone());
    execute(
        &pool,
        "ALTER TABLE iam_security_audit_chain_head DROP CONSTRAINT iam_security_audit_chain_head_hash_check",
    )
    .await
    .unwrap();
    execute(
        &pool,
        "UPDATE iam_security_audit_chain_head SET hash = decode('00ff', 'hex')",
    )
    .await
    .unwrap();

    let head = log.chain_head().await.unwrap_err();
    let append = log
        .append_batch(std::slice::from_ref(&event))
        .await
        .unwrap_err();

    assert!(matches!(head, RepositoryError::Unavailable(_)));
    assert!(matches!(append, RepositoryError::Unavailable(_)));
    assert_eq!(all_records(&log).await.len(), 0);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_missing_chain_head_is_unavailable(pool: PgPool) {
    let event = security_audit_event(&mut TestRng::from_env());
    let log = PgSecurityAuditLog::new(pool.clone());
    execute(&pool, "DELETE FROM iam_security_audit_chain_head")
        .await
        .unwrap();

    let head = log.chain_head().await.unwrap_err();
    let append = log
        .append_batch(std::slice::from_ref(&event))
        .await
        .unwrap_err();

    assert!(matches!(head, RepositoryError::Unavailable(_)));
    assert!(matches!(append, RepositoryError::Unavailable(_)));
}

#[tokio::test]
async fn an_unreachable_database_is_unavailable() {
    let event = security_audit_event(&mut TestRng::from_env());
    let pool = connect_lazy(&PostgresSettings {
        url: DEAD_DATABASE_URL.to_owned(),
        max_connections: 1,
        acquire_timeout: Duration::from_millis(500),
        statement_timeout: Duration::from_secs(1),
    })
    .unwrap();
    let log = PgSecurityAuditLog::new(pool);

    let append = log
        .append_batch(std::slice::from_ref(&event))
        .await
        .unwrap_err();
    let head = log.chain_head().await.unwrap_err();
    let found = log
        .search(&search(SecurityAuditFilter::new(), None, 1))
        .await
        .unwrap_err();

    assert!(matches!(append, RepositoryError::Unavailable(_)));
    assert!(matches!(head, RepositoryError::Unavailable(_)));
    assert!(matches!(found, RepositoryError::Unavailable(_)));
    assert_eq!(append.to_string(), "the repository is unavailable");
}
