use std::error::Error as _;

use rstest::rstest;

use super::*;

const DIGEST: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

fn row() -> Row {
    Row {
        version: 3,
        digest: DIGEST.to_vec(),
        log_epoch: 5,
        relay_epoch: 7,
        catalog_epoch: 11,
    }
}

#[test]
fn a_valid_row_is_restored_with_every_column() {
    let epoch = restore(&row()).unwrap();

    assert_eq!(epoch.version().value(), 3);
    assert_eq!(epoch.digest().as_bytes(), &DIGEST);
    assert_eq!(epoch.log_epoch().value(), 5);
    assert_eq!(epoch.relay_epoch().value(), 7);
    assert_eq!(epoch.catalog_epoch(), 11);
}

#[rstest]
#[case::negative_version(Row { version: -1, ..row() }, "This value must be 0 or greater.")]
#[case::short_digest(
    Row { digest: vec![0; 15], ..row() },
    "This value must contain exactly 16 bytes."
)]
#[case::long_digest(
    Row { digest: vec![0; 17], ..row() },
    "This value must contain exactly 16 bytes."
)]
#[case::negative_log_epoch(Row { log_epoch: -1, ..row() }, "This value must be 0 or greater.")]
#[case::negative_relay_epoch(Row { relay_epoch: -1, ..row() }, "This value must be 0 or greater.")]
#[case::negative_catalog_epoch(
    Row { catalog_epoch: -1, ..row() },
    "This value must be 0 or greater."
)]
fn a_row_that_breaks_a_domain_invariant_is_unavailable(#[case] row: Row, #[case] cause: &str) {
    let error = restore(&row).unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
    assert_eq!(error.source().unwrap().to_string(), cause);
}

#[test]
fn a_missing_row_is_not_found() {
    let error = translate(sqlx::Error::RowNotFound);

    assert!(matches!(error, RepositoryError::NotFound));
}

#[test]
fn any_other_database_error_is_unavailable() {
    let error = translate(sqlx::Error::PoolTimedOut);

    assert!(matches!(error, RepositoryError::Unavailable(_)));
    assert_eq!(error.to_string(), "the repository is unavailable");
    assert!(error.source().is_some());
}
