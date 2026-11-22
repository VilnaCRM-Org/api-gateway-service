//! Ports of the IAM context and the error they share.

pub mod access_token_verifier;
pub mod boot_clock;
pub mod change_receipt_repository;
pub mod graphql_schema_parser;
pub mod graphql_spec_repository;
pub mod iam_unit_of_work;
pub mod idempotency_repository;
pub mod openapi_document_parser;
pub mod openapi_spec_repository;
pub mod policy_epoch_repository;
pub mod revocation_repository;
pub mod revocation_view;
pub mod rng;
pub mod role_repository;
pub mod security_audit_log;
pub mod token_memo;
pub mod token_repository;
pub mod user_role_repository;

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
