use std::time::Duration;

use iam_domain::{
    ChangeId, PolicyVersion, PropagationOutcome, PropagationStore as _, RepositoryError,
};
use shared_domain::Uuid;
use sqlx::postgres::PgPoolOptions;

use super::PgPropagationStore;

/// A store over a pool whose connections are never opened: every statement fails to acquire one.
fn unreachable_store() -> PgPropagationStore {
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(50))
        .connect_lazy("postgres://iam:iam@127.0.0.1:1/iam")
        .unwrap();
    PgPropagationStore::new(pool)
}

#[tokio::test]
async fn every_statement_against_an_unreachable_database_is_unavailable() {
    let store = unreachable_store();
    let change = ChangeId::from_uuid(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ad").unwrap());

    assert!(matches!(
        store
            .published_head_offset(PolicyVersion::new(1).unwrap())
            .await,
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        store
            .record(change, PropagationOutcome::CommittedPending)
            .await,
        Err(RepositoryError::Unavailable(_))
    ));
}
