use std::error::Error as _;
use std::time::SystemTime;

use iam_domain::{AntiEntropyStore as _, InvalidIamValue, RepositoryError};
use shared_domain::Uuid;
use sqlx::postgres::PgPoolOptions;

use super::{PgAntiEntropyStore, count_of, negative, unavailable, unusable};

/// A pool whose connections are never opened: every statement fails to acquire one.
fn unreachable_store() -> PgAntiEntropyStore {
    let pool = PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(50))
        .connect_lazy("postgres://iam:iam@127.0.0.1:1/iam")
        .unwrap();
    PgAntiEntropyStore::new(pool)
}

#[test]
fn a_failed_statement_is_an_unavailable_storage() {
    let error = unavailable(sqlx::Error::PoolTimedOut);

    assert!(matches!(error, RepositoryError::Unavailable(_)));
    assert!(error.source().is_some());
}

#[test]
fn a_value_that_breaks_an_invariant_is_unusable_data() {
    let error = unusable(InvalidIamValue::PolicyVersionNegative);

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}

#[test]
fn a_stored_count_is_unsigned_and_a_negative_one_is_unusable_data() {
    assert_eq!(count_of(3).unwrap(), 3);
    assert!(matches!(count_of(-1), Err(RepositoryError::Unavailable(_))));
}

#[test]
fn a_negative_number_is_unusable_data() {
    let error = negative();

    assert!(error.source().is_some());
}

#[tokio::test]
async fn every_read_of_an_unreachable_database_is_unavailable() {
    let store = unreachable_store();
    let id = Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ad").unwrap();

    assert!(matches!(
        store.head().await,
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        store.recently_published(SystemTime::UNIX_EPOCH, 5).await,
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        store.keys_written_since(SystemTime::UNIX_EPOCH).await,
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        store.unpublished_count().await,
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        store.republish(id).await,
        Err(RepositoryError::Unavailable(_))
    ));
}
