use std::time::Duration;

use iam_domain::{RepositoryError, TokenLifetimeFloor as _};
use sqlx::postgres::PgPoolOptions;

use super::{PgTokenLifetimeFloor, lifetime_of, out_of_range};

/// A store over a pool whose connections are never opened: every statement fails to acquire one.
fn unreachable_store() -> PgTokenLifetimeFloor {
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(50))
        .connect_lazy("postgres://iam:iam@127.0.0.1:1/iam")
        .unwrap();
    PgTokenLifetimeFloor::new(pool)
}

#[test]
fn a_positive_number_of_seconds_is_a_lifetime() {
    assert_eq!(lifetime_of(1_800).unwrap(), Duration::from_mins(30));
}

#[test]
fn a_stored_value_that_is_not_positive_is_unusable() {
    assert!(lifetime_of(0).is_err());
    assert!(lifetime_of(-5).is_err());
}

#[test]
fn an_out_of_range_lifetime_is_unavailable() {
    assert!(matches!(out_of_range(), RepositoryError::Unavailable(_)));
}

#[tokio::test]
async fn a_configured_lifetime_above_the_column_range_is_refused_before_any_statement() {
    let refused = unreachable_store().raise_to(Duration::MAX).await;

    assert!(matches!(refused, Err(RepositoryError::Unavailable(_))));
}
