//! `PgChangeReceiptRepository` and `PgIdempotencyRepository`: reading back the receipt and the
//! idempotency record of a committed change, the 24-hour replay window and the expiry of a key.

use std::time::{Duration, SystemTime};

use iam_domain::{
    ChangeReceiptRepository as _, DecisionEffect, IamChange, IamUnitOfWork as _, IdempotencyRecord,
    IdempotencyRepository as _, PolicyVersion, RepositoryError, SecurityAuditEvent,
};
use iam_infrastructure::{PgChangeReceiptRepository, PgIamUnitOfWork, PgIdempotencyRepository};
use shared_infrastructure::persistence::{PostgresSettings, connect_lazy};
use sqlx::PgPool;
use test_support::change_receipt::change_receipt;
use test_support::seed::TestRng;
use test_support::unit_of_work::{iam_change, rebuilt};

/// URL that nothing listens on: the "unreachable database" case. No container is stopped.
const DEAD_DATABASE_URL: &str = "postgres://app:unused@127.0.0.1:1/app";

/// The rows of the outbox, the audit log, the receipts and the idempotency keys.
async fn counts(pool: &PgPool) -> (i64, i64, i64, i64) {
    sqlx::query_as(
        "SELECT (SELECT count(*) FROM iam_outbox), (SELECT count(*) FROM iam_security_audit_events), \
         (SELECT count(*) FROM iam_change_receipts), (SELECT count(*) FROM iam_idempotency_keys)",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

/// When the change happened.
fn occurred_at(change: &IamChange) -> SystemTime {
    change.parts().audit.parts().occurred_at
}

/// Another change of the same actor with the same idempotency key and request digest, `after`
/// the first one.
fn repeat_after(rng: &mut TestRng, first: &IamChange, after: Duration) -> IamChange {
    rebuilt(&iam_change(rng, DecisionEffect::Affected, 1), |parts| {
        let mut audit = first.parts().audit.parts().clone();
        audit.id = parts.audit.parts().id;
        audit.occurred_at = occurred_at(first).checked_add(after).unwrap();
        parts.audit = SecurityAuditEvent::record(audit).unwrap();
        parts.idempotency = first.parts().idempotency.clone();
    })
}

fn dead_pool() -> PgPool {
    connect_lazy(&PostgresSettings {
        url: DEAD_DATABASE_URL.to_owned(),
        max_connections: 1,
        acquire_timeout: Duration::from_millis(500),
        statement_timeout: Duration::from_secs(1),
    })
    .unwrap()
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_receipt_of_a_committed_change_is_read_back(pool: PgPool) {
    let change = iam_change(&mut TestRng::from_env(), DecisionEffect::Affected, 1);
    let receipt = PgIamUnitOfWork::new(pool.clone())
        .commit(change.clone())
        .await
        .unwrap();

    let found = PgChangeReceiptRepository::new(pool)
        .find(change.parts().change_id)
        .await
        .unwrap();

    assert_eq!(found, receipt);
    assert_eq!(found.policy_version(), PolicyVersion::new(1).ok());
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_receipt_of_a_change_that_did_not_affect_decisions_has_no_policy_version(pool: PgPool) {
    let change = iam_change(&mut TestRng::from_env(), DecisionEffect::Unaffected, 1);
    PgIamUnitOfWork::new(pool.clone())
        .commit(change.clone())
        .await
        .unwrap();

    let found = PgChangeReceiptRepository::new(pool)
        .find(change.parts().change_id)
        .await
        .unwrap();

    assert_eq!(found.policy_version(), None);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_unknown_change_has_no_receipt(pool: PgPool) {
    let receipt = change_receipt(&mut TestRng::from_env());

    let error = PgChangeReceiptRepository::new(pool)
        .find(receipt.change_id())
        .await
        .unwrap_err();

    assert!(matches!(error, RepositoryError::NotFound));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_stored_receipt_that_breaks_an_invariant_is_unavailable(pool: PgPool) {
    let change = iam_change(&mut TestRng::from_env(), DecisionEffect::Affected, 0);
    PgIamUnitOfWork::new(pool.clone())
        .commit(change.clone())
        .await
        .unwrap();
    sqlx::query("UPDATE iam_change_receipts SET actor = 'robot:1'")
        .execute(&pool)
        .await
        .unwrap();

    let error = PgChangeReceiptRepository::new(pool)
        .find(change.parts().change_id)
        .await
        .unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_repeat_within_24_hours_finds_the_original_change_and_writes_nothing(pool: PgPool) {
    let change = iam_change(&mut TestRng::from_env(), DecisionEffect::Affected, 2);
    let receipt = PgIamUnitOfWork::new(pool.clone())
        .commit(change.clone())
        .await
        .unwrap();
    let record = change.idempotency_record().unwrap();
    let before = counts(&pool).await;
    let now = occurred_at(&change)
        .checked_add(Duration::from_secs(86_399))
        .unwrap();

    let found = PgIdempotencyRepository::new(pool.clone())
        .find_since(
            record.actor(),
            record.key(),
            IdempotencyRecord::window_start(now),
        )
        .await
        .unwrap()
        .unwrap();
    let original = PgChangeReceiptRepository::new(pool.clone())
        .find(found.replay(record.request_digest()).unwrap())
        .await
        .unwrap();

    assert_eq!(found, record);
    assert_eq!(original, receipt);
    assert_eq!(before, (2, 1, 1, 1));
    assert_eq!(counts(&pool).await, before);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_repeat_of_a_live_key_cannot_commit_a_second_change(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let first = iam_change(&mut rng, DecisionEffect::Affected, 1);
    let repeat = repeat_after(&mut rng, &first, Duration::from_secs(86_399));
    let unit = PgIamUnitOfWork::new(pool.clone());
    unit.commit(first).await.unwrap();
    let before = counts(&pool).await;

    let error = unit.commit(repeat).await.unwrap_err();

    assert!(matches!(error, RepositoryError::AlreadyExists));
    assert_eq!(counts(&pool).await, before);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_record_older_than_24_hours_is_not_found_and_its_key_starts_a_new_change(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let first = iam_change(&mut rng, DecisionEffect::Affected, 1);
    let later = Duration::from_secs(86_401);
    let repeat = repeat_after(&mut rng, &first, later);
    let unit = PgIamUnitOfWork::new(pool.clone());
    unit.commit(first.clone()).await.unwrap();
    let record = first.idempotency_record().unwrap();
    let keys = PgIdempotencyRepository::new(pool.clone());
    let now = occurred_at(&first).checked_add(later).unwrap();

    let expired = keys
        .find_since(
            record.actor(),
            record.key(),
            IdempotencyRecord::window_start(now),
        )
        .await
        .unwrap();
    let receipt = unit.commit(repeat.clone()).await.unwrap();
    let renewed = keys
        .find_since(
            record.actor(),
            record.key(),
            IdempotencyRecord::window_start(now),
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(expired, None);
    assert_eq!(receipt.change_id(), repeat.parts().change_id);
    assert_eq!(renewed, repeat.idempotency_record().unwrap());
    assert_eq!(counts(&pool).await, (2, 2, 2, 1));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_record_created_exactly_at_the_window_start_still_replays(pool: PgPool) {
    let change = iam_change(&mut TestRng::from_env(), DecisionEffect::Affected, 0);
    PgIamUnitOfWork::new(pool.clone())
        .commit(change.clone())
        .await
        .unwrap();
    let record = change.idempotency_record().unwrap();
    let keys = PgIdempotencyRepository::new(pool);

    let at_start = keys
        .find_since(record.actor(), record.key(), occurred_at(&change))
        .await
        .unwrap();
    let after_start = keys
        .find_since(
            record.actor(),
            record.key(),
            occurred_at(&change)
                .checked_add(Duration::from_micros(1))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(at_start, Some(record));
    assert_eq!(after_start, None);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_key_of_another_actor_or_another_key_is_not_found(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let change = iam_change(&mut rng, DecisionEffect::Affected, 0);
    let other = iam_change(&mut rng, DecisionEffect::Affected, 0);
    PgIamUnitOfWork::new(pool.clone())
        .commit(change.clone())
        .await
        .unwrap();
    let record = change.idempotency_record().unwrap();
    let other_record = other.idempotency_record().unwrap();
    let keys = PgIdempotencyRepository::new(pool);

    let by_other_actor = keys
        .find_since(other_record.actor(), record.key(), SystemTime::UNIX_EPOCH)
        .await
        .unwrap();
    let by_other_key = keys
        .find_since(record.actor(), other_record.key(), SystemTime::UNIX_EPOCH)
        .await
        .unwrap();

    assert_eq!(by_other_actor, None);
    assert_eq!(by_other_key, None);
}

#[tokio::test]
async fn an_unreachable_database_is_unavailable_for_both_repositories() {
    let change = iam_change(&mut TestRng::from_env(), DecisionEffect::Affected, 0);
    let record = change.idempotency_record().unwrap();

    let receipt_error = PgChangeReceiptRepository::new(dead_pool())
        .find(change.parts().change_id)
        .await
        .unwrap_err();
    let key_error = PgIdempotencyRepository::new(dead_pool())
        .find_since(record.actor(), record.key(), SystemTime::UNIX_EPOCH)
        .await
        .unwrap_err();

    assert!(matches!(receipt_error, RepositoryError::Unavailable(_)));
    assert!(matches!(key_error, RepositoryError::Unavailable(_)));
}
