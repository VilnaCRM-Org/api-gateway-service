//! PostgreSQL implementation of the bulk role target port: the `iam_bulk_role_targets` table.
//!
//! The statements are checked at run time, so the offline query metadata does not hold them.

use iam_domain::{BulkOperationId, BulkRoleTargetStore, RepositoryError, RoleId};
use shared_domain::Uuid;
use sqlx::types::Uuid as SqlUuid;

use crate::persistence::role::translate;

const INSERT: &str = "INSERT INTO iam_bulk_role_targets (operation_id, role_id) VALUES ($1, $2)";

const SELECT: &str = "SELECT role_id FROM iam_bulk_role_targets WHERE operation_id = $1";

/// Stores the role that each role-deletion bulk operation deletes.
#[derive(Debug)]
pub struct PgBulkRoleTargetStore {
    pool: sqlx::PgPool,
}

impl PgBulkRoleTargetStore {
    /// Builds the store over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl BulkRoleTargetStore for PgBulkRoleTargetStore {
    async fn insert(
        &self,
        operation: BulkOperationId,
        role: RoleId,
    ) -> Result<(), RepositoryError> {
        sqlx::query(INSERT)
            .bind(operation.as_uuid().as_uuid())
            .bind(role.as_uuid().as_uuid())
            .execute(&self.pool)
            .await
            .map(|_done| ())
            .map_err(translate)
    }

    async fn find(&self, operation: BulkOperationId) -> Result<Option<RoleId>, RepositoryError> {
        let role: Option<SqlUuid> = sqlx::query_scalar(SELECT)
            .bind(operation.as_uuid().as_uuid())
            .fetch_optional(&self.pool)
            .await
            .map_err(translate)?;
        Ok(role.map(|role| RoleId::from_uuid(Uuid::from_uuid(role))))
    }
}
