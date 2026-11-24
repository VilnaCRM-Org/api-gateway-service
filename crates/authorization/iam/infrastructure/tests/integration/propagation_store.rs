//! `PgPropagationStore`: the stored offset of the `__head` row of a version and the propagation
//! outcome that a change receipt keeps and a replay reads back.

use iam_domain::{
    ChangeReceiptRepository as _, DecisionEffect, IamUnitOfWork as _, OutboxStore as _,
    PolicyVersion, PropagationOutcome, PropagationStore as _, PublishedRow, RepositoryError,
    WriteMode,
};
use iam_infrastructure::{
    PgChangeReceiptRepository, PgIamUnitOfWork, PgOutboxStore, PgPropagationStore,
};
use shared_domain::Uuid;
use sqlx::PgPool;
use sqlx::types::Uuid as SqlUuid;
use test_support::seed::TestRng;
use test_support::unit_of_work::iam_change;

fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

/// Inserts the unpublished `__head` row of `version`.
async fn head_row(pool: &PgPool, id: SqlUuid, version: i64) {
    sqlx::query(
        "INSERT INTO iam_outbox (id, kind, topic, record_key, payload, policy_version, seq, count,
            digest_after, log_epoch, occurred_at)
        VALUES ($1, 'state', 'iam.policy.state.v1', '__head', '{}', $2, 1, 1,
            decode(repeat('00', 16), 'hex'), 0, now())",
    )
    .bind(id)
    .bind(version)
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_head_row_has_an_offset_only_once_the_relay_marked_it_published(pool: PgPool) {
    let id = SqlUuid::from_u128(0x0190_f2a8_7b3c_7d4e_8f10_0000_0000_0001);
    head_row(&pool, id, 1).await;
    let store = PgPropagationStore::new(pool.clone());
    assert_eq!(store.published_head_offset(version(1)).await.unwrap(), None);

    let outbox = PgOutboxStore::new(pool);
    let epoch = outbox.current_relay_epoch().await.unwrap();
    outbox
        .mark_published(
            &[PublishedRow {
                id: Uuid::from_uuid(id),
                offset: 42,
            }],
            epoch,
            std::time::SystemTime::UNIX_EPOCH,
        )
        .await
        .unwrap();

    assert_eq!(
        store.published_head_offset(version(1)).await.unwrap(),
        Some(42)
    );
    assert_eq!(store.published_head_offset(version(2)).await.unwrap(), None);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_recorded_outcome_is_read_back_with_the_receipt(pool: PgPool) {
    let change = iam_change(&mut TestRng::from_env(), DecisionEffect::Affected, 1);
    let receipt = PgIamUnitOfWork::new(pool.clone())
        .commit(change, WriteMode::Published)
        .await
        .unwrap();
    let store = PgPropagationStore::new(pool.clone());
    let receipts = PgChangeReceiptRepository::new(pool);
    assert_eq!(
        receipts
            .find(receipt.change_id())
            .await
            .unwrap()
            .propagation(),
        None
    );

    store
        .record(
            receipt.change_id(),
            PropagationOutcome::Published { offset: 7 },
        )
        .await
        .unwrap();

    assert_eq!(
        receipts
            .find(receipt.change_id())
            .await
            .unwrap()
            .propagation(),
        Some(PropagationOutcome::Published { offset: 7 })
    );

    store
        .record(receipt.change_id(), PropagationOutcome::CommittedPending)
        .await
        .unwrap();

    assert_eq!(
        receipts
            .find(receipt.change_id())
            .await
            .unwrap()
            .propagation(),
        Some(PropagationOutcome::CommittedPending)
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_outcome_for_an_unknown_change_is_not_found(pool: PgPool) {
    let change = iam_change(&mut TestRng::from_env(), DecisionEffect::Affected, 0);
    let store = PgPropagationStore::new(pool);

    let error = store
        .record(
            change.parts().change_id,
            PropagationOutcome::CommittedPending,
        )
        .await
        .unwrap_err();

    assert!(matches!(error, RepositoryError::NotFound));
}
