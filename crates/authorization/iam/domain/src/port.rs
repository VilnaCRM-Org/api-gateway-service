//! Ports of the IAM context and the error they share.

pub mod access_token_verifier;
pub mod anti_entropy_store;
pub mod boot_clock;
pub mod bulk_chunk_committer;
pub mod bulk_operation_repository;
pub mod bulk_role_target_store;
pub mod change_receipt_repository;
pub mod endpoint_watch;
pub mod expired_revocation_store;
pub mod graphql_document_analyzer;
pub mod graphql_permission_repository;
pub mod graphql_schema_parser;
pub mod graphql_spec_repository;
pub mod iam_unit_of_work;
pub mod idempotency_repository;
pub mod kafka_topic_inspector;
pub mod local_rate_limiter;
pub mod maintenance_store;
pub mod openapi_document_parser;
pub mod openapi_spec_repository;
pub mod outbox_store;
pub mod peer_freshness_client;
pub mod permission_page_query;
pub mod policy_bootstrap_log;
pub mod policy_digest;
pub mod policy_epoch_repository;
pub mod policy_log_probe;
pub mod policy_log_producer;
pub mod policy_log_tail;
pub mod policy_read_repository;
pub mod policy_state_inventory;
pub mod policy_tail_log;
pub mod policy_view;
pub mod propagation_store;
pub mod rate_limit_store;
pub mod rate_policy_repository;
pub mod rejected_attempt_log;
pub mod request_digester;
pub mod rest_permission_repository;
pub mod revocation_repository;
pub mod revocation_view;
pub mod rng;
pub mod role_repository;
pub mod route_repository;
pub mod route_table_compiler;
pub mod security_audit_log;
pub mod singleton_leadership;
pub mod startup_lock;
pub mod state_record_codec;
pub mod task_state_repository;
pub mod token_lifetime_floor;
pub mod token_memo;
pub mod token_repository;
pub mod upstream_repository;
pub mod user_role_repository;

use shared_domain::BoxError;

use crate::error::{ReferencedByRoute, RouteConflict};

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
    /// A guard of the change refused it: its actor lacks the administrative rights the change
    /// needs (the application answers 403).
    #[error("the actor lacks the administrative rights of the change")]
    Forbidden,
    /// A route still references the upstream or the rate policy that the change deletes: the
    /// transaction found the reference under the lock of the policy epoch (the application
    /// answers 409).
    #[error("a route still references the entry")]
    ReferencedByRoute(#[source] ReferencedByRoute),
    /// The route table of the host, rebuilt under the lock of the policy epoch with the route of
    /// the change in it, has a conflict or cannot be compiled (the application answers 409).
    #[error("the route table of the host has a conflict")]
    RouteTable(#[source] RouteConflict),
    /// The storage cannot be reached, answered with a failure or holds unusable data.
    #[error("the repository is unavailable")]
    Unavailable(#[source] BoxError),
}

#[cfg(test)]
mod tests;
