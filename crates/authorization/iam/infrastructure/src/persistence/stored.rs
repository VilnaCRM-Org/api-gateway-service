//! What the adapters of the gateway configuration share: the errors of a stored value that the
//! domain refuses and the translation of a violated reference.

use std::error::Error;

use iam_domain::{InvalidStateRecord, RepositoryError};

use crate::persistence::role::translate;

/// A stored column or state field that the domain refuses is unusable data.
pub(crate) fn unusable_field(field: &'static str) -> RepositoryError {
    RepositoryError::Unavailable(Box::new(InvalidStateRecord::Field { field }))
}

/// A stored value that breaks a domain invariant is unusable data.
pub(crate) fn unusable_value<E>(error: E) -> RepositoryError
where
    E: Error + Send + Sync + 'static,
{
    RepositoryError::Unavailable(Box::new(error))
}

/// The count of a `count(*)` query.
pub(crate) fn count_of(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_error| unusable_field("count"))
}

/// A foreign key violation means the record that the statement names is not stored: the statement
/// does not hold, a conflict; every other error is translated as by the role adapter.
pub(crate) fn translate_reference(error: sqlx::Error) -> RepositoryError {
    let missing = error
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_foreign_key_violation);
    if missing {
        RepositoryError::Conflict
    } else {
        translate(error)
    }
}

#[cfg(test)]
mod tests;
