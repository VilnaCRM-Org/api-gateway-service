//! Ports of the IAM context and the error they share.

pub mod boot_clock;
pub mod iam_unit_of_work;
pub mod policy_epoch_repository;
pub mod rng;
pub mod security_audit_log;

use shared_domain::BoxError;

/// A repository operation failed.
#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    /// A record with the same identity or unique value is already stored.
    #[error("the record already exists")]
    AlreadyExists,
    /// The record that must exist is not stored.
    #[error("the record was not found")]
    NotFound,
    /// The record was changed by another writer since it was read.
    #[error("the record was changed concurrently")]
    Conflict,
    /// The storage cannot be reached, answered with a failure or holds unusable data.
    #[error("the repository is unavailable")]
    Unavailable(#[source] BoxError),
}

#[cfg(test)]
mod tests;
