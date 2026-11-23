use std::error::Error as _;

use iam_domain::RepositoryError;

use super::{count_of, translate_reference, unusable_field, unusable_value};

#[test]
fn an_unusable_field_is_unavailable_with_its_name() {
    let error = unusable_field("protocol");

    assert!(matches!(error, RepositoryError::Unavailable(_)));
    assert_eq!(
        error.source().unwrap().to_string(),
        "The state field protocol is missing or invalid."
    );
}

#[test]
fn an_unusable_value_is_unavailable_with_its_cause() {
    let error = unusable_value(iam_domain::InvalidStateRecord::Encoding);

    assert!(matches!(error, RepositoryError::Unavailable(_)));
    assert_eq!(
        error.source().unwrap().to_string(),
        "The state cannot be encoded."
    );
}

#[test]
fn a_count_is_never_negative() {
    assert_eq!(count_of(0).unwrap(), 0);
    assert_eq!(count_of(7).unwrap(), 7);
    assert!(matches!(count_of(-1), Err(RepositoryError::Unavailable(_))));
}

/// A database error of a given kind, as PostgreSQL reports a violated constraint.
#[derive(Debug)]
struct Violation(fn() -> sqlx::error::ErrorKind);

impl std::fmt::Display for Violation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("constraint violated")
    }
}

impl std::error::Error for Violation {}

impl sqlx::error::DatabaseError for Violation {
    fn message(&self) -> &'static str {
        "constraint violated"
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
        (self.0)()
    }
}

#[test]
fn a_missing_referenced_record_is_a_conflict() {
    let error = sqlx::Error::Database(Box::new(Violation(|| {
        sqlx::error::ErrorKind::ForeignKeyViolation
    })));

    assert!(matches!(
        translate_reference(error),
        RepositoryError::Conflict
    ));
}

#[test]
fn a_unique_violation_is_a_duplicate_and_any_other_error_is_unavailable() {
    let unique = sqlx::Error::Database(Box::new(Violation(|| {
        sqlx::error::ErrorKind::UniqueViolation
    })));
    let other = sqlx::Error::Database(Box::new(Violation(|| sqlx::error::ErrorKind::Other)));

    assert!(matches!(
        translate_reference(unique),
        RepositoryError::AlreadyExists
    ));
    assert!(matches!(
        translate_reference(other),
        RepositoryError::Unavailable(_)
    ));
    assert!(matches!(
        translate_reference(sqlx::Error::PoolTimedOut),
        RepositoryError::Unavailable(_)
    ));
}
