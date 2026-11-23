use std::error::Error as _;
use std::time::{Duration, UNIX_EPOCH};

use iam_domain::{InvalidEventEnvelope, InvalidIamValue, RepositoryError};
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;

use super::{
    restore_epoch, restore_head, restore_orphan, translate, unavailable, unencodable, unusable,
};

const ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";

fn role_id() -> SqlUuid {
    SqlUuid::parse_str(ROLE).unwrap()
}

#[test]
fn a_database_failure_is_an_unavailable_repository_with_its_cause() {
    let error = unavailable(sqlx::Error::PoolTimedOut);

    assert!(matches!(error, RepositoryError::Unavailable(_)));
    assert!(error.source().is_some());
}

#[test]
fn a_failure_that_is_no_unique_violation_is_an_unavailable_repository() {
    let error = translate(sqlx::Error::RowNotFound);

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}

#[test]
fn a_value_that_breaks_an_invariant_is_unusable_data() {
    let stored = unusable(InvalidIamValue::AuditHashLength);
    let event = unencodable(InvalidEventEnvelope::TooLarge);

    assert!(matches!(stored, RepositoryError::Unavailable(_)));
    assert!(matches!(event, RepositoryError::Unavailable(_)));
}

#[test]
fn a_stored_row_becomes_an_orphaned_grant() {
    let orphaned_at = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();

    let orphan = restore_orphan(role_id(), "rest:billing:GET /invoices", orphaned_at).unwrap();

    assert_eq!(orphan.role_id.to_string(), ROLE);
    assert_eq!(orphan.grant.to_string(), "rest:billing:GET /invoices");
    assert_eq!(
        orphan.orphaned_at,
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    );
}

#[test]
fn a_stored_key_that_is_no_grant_is_unusable_data() {
    let orphaned_at = OffsetDateTime::from_unix_timestamp(0).unwrap();

    let error = restore_orphan(role_id(), "not a key", orphaned_at).unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}

#[test]
fn a_stored_head_keeps_its_sequence_number_and_hash() {
    let head = restore_head(5, &[9; 32]).unwrap();

    assert_eq!(head.seq(), 5);
    assert_eq!(head.hash().as_bytes(), &[9; 32]);
}

#[test]
fn a_head_with_a_short_hash_or_a_negative_sequence_is_unusable_data() {
    assert!(matches!(
        restore_head(5, &[9; 31]),
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        restore_head(-1, &[9; 32]),
        Err(RepositoryError::Unavailable(_))
    ));
}

#[test]
fn a_stored_epoch_keeps_its_version_and_log_epoch() {
    let (version, log_epoch) = restore_epoch(7, 2).unwrap();

    assert_eq!(version.value(), 7);
    assert_eq!(log_epoch.value(), 2);
}

#[test]
fn a_negative_version_or_log_epoch_is_unusable_data() {
    assert!(matches!(
        restore_epoch(-1, 2),
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        restore_epoch(1, -2),
        Err(RepositoryError::Unavailable(_))
    ));
}

/// A database error that reports a unique violation, as PostgreSQL does for an event id stored
/// already.
#[derive(Debug)]
struct UniqueViolation;

impl std::fmt::Display for UniqueViolation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("duplicate key value violates unique constraint")
    }
}

impl std::error::Error for UniqueViolation {}

impl sqlx::error::DatabaseError for UniqueViolation {
    fn message(&self) -> &'static str {
        "duplicate key value violates unique constraint"
    }

    fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        self
    }

    fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
        self
    }

    fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
        self
    }

    fn kind(&self) -> sqlx::error::ErrorKind {
        sqlx::error::ErrorKind::UniqueViolation
    }
}

#[test]
fn a_unique_violation_is_a_duplicate() {
    let error = translate(sqlx::Error::Database(Box::new(UniqueViolation)));

    assert!(matches!(error, RepositoryError::AlreadyExists));
}
