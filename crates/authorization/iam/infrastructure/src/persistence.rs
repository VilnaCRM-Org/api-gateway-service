//! PostgreSQL implementation of the policy epoch repository port: the SQL, the row mapping and the
//! translation of database errors.

pub mod advisory_lock_leadership;
pub mod anti_entropy_store;
pub mod bulk_operation;
pub mod catalogue;
pub mod change_receipt;
pub mod event_encoding;
pub mod gateway_configuration;
pub mod graphql_permission;
pub mod graphql_spec;
pub mod idempotency;
pub mod maintenance_store;
pub mod openapi_spec;
pub mod outbox_listener;
pub mod outbox_store;
pub mod policy_read;
pub mod propagation_store;
pub mod rate_policy;
pub mod rest_permission;
pub mod revocation;
pub mod revocation_view;
pub mod role;
pub mod route;
pub mod security_audit_log;
pub mod startup_lock;
pub mod state_writer;
pub(crate) mod stored;
pub mod task_state;
pub mod unit_of_work;
pub mod upstream;
pub mod user_role;

use iam_domain::{
    InvalidIamValue, LogEpoch, PolicyDigestValue, PolicyEpoch, PolicyEpochRepository,
    PolicyVersion, RelayEpoch, RepositoryError,
};

/// Reads the policy epoch from the single row of the `iam_policy_epoch` table.
#[derive(Debug)]
pub struct PgPolicyEpochRepository {
    pool: sqlx::PgPool,
}

/// The stored row; it never leaves this module.
struct Row {
    version: i64,
    digest: Vec<u8>,
    log_epoch: i64,
    relay_epoch: i64,
    catalog_epoch: i64,
}

impl PgPolicyEpochRepository {
    /// Builds the repository over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    async fn select_current(&self) -> Result<PolicyEpoch, RepositoryError> {
        let row = sqlx::query_as!(
            Row,
            "SELECT version, digest, log_epoch, relay_epoch, catalog_epoch FROM iam_policy_epoch WHERE id = 1",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(translate)?;
        restore(&row)
    }
}

/// A query that found no row is a missing record; everything else, a pool acquire timeout
/// included, is an unavailable repository.
fn translate(error: sqlx::Error) -> RepositoryError {
    if matches!(error, sqlx::Error::RowNotFound) {
        RepositoryError::NotFound
    } else {
        RepositoryError::Unavailable(Box::new(error))
    }
}

/// A stored value that breaks a domain invariant is unusable data.
fn unusable(error: InvalidIamValue) -> RepositoryError {
    RepositoryError::Unavailable(Box::new(error))
}

/// Rebuilds the epoch of the stored row through the value objects.
fn restore(row: &Row) -> Result<PolicyEpoch, RepositoryError> {
    let version = PolicyVersion::new(row.version).map_err(unusable)?;
    let digest = PolicyDigestValue::new(&row.digest).map_err(unusable)?;
    let log_epoch = LogEpoch::new(row.log_epoch).map_err(unusable)?;
    let relay_epoch = RelayEpoch::new(row.relay_epoch).map_err(unusable)?;
    PolicyEpoch::new(version, digest, log_epoch, relay_epoch, row.catalog_epoch).map_err(unusable)
}

#[async_trait::async_trait]
impl PolicyEpochRepository for PgPolicyEpochRepository {
    async fn current(&self) -> Result<PolicyEpoch, RepositoryError> {
        self.select_current().await
    }
}

#[cfg(test)]
mod tests;
