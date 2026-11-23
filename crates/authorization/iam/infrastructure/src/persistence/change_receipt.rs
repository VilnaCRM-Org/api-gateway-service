//! PostgreSQL implementation of the change receipt repository port: reads `iam_change_receipts`,
//! which the unit of work writes.

use iam_domain::{
    ActorRef, AuditTarget, ChangeId, ChangeReceipt, ChangeReceiptRepository, EntityVersion,
    InvalidIamValue, PolicyVersion, RepositoryError,
};

/// Reads the change receipts from the `iam_change_receipts` table.
#[derive(Debug)]
pub struct PgChangeReceiptRepository {
    pool: sqlx::PgPool,
}

/// The stored row; it never leaves this module.
struct Row {
    actor: String,
    target_type: String,
    target_id: String,
    entity_version: i64,
    policy_version: Option<i64>,
    revoked_assignments: Option<i32>,
}

impl PgChangeReceiptRepository {
    /// Builds the repository over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    async fn select(&self, change_id: ChangeId) -> Result<ChangeReceipt, RepositoryError> {
        let id = change_id.as_uuid().as_uuid();
        let row = sqlx::query_as!(
            Row,
            "SELECT actor, target_type, target_id, entity_version, policy_version,
                revoked_assignments
            FROM iam_change_receipts WHERE change_id = $1",
            id,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(translate)?;
        restore(change_id, &row)
    }
}

/// A query that found no row is a missing receipt; everything else, a pool acquire timeout
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

/// Rebuilds the receipt of the stored row through the value objects.
fn restore(change_id: ChangeId, row: &Row) -> Result<ChangeReceipt, RepositoryError> {
    let actor = ActorRef::parse(&row.actor).map_err(unusable)?;
    let target = AuditTarget::new(&row.target_type, &row.target_id).map_err(unusable)?;
    let entity_version = EntityVersion::new(row.entity_version).map_err(unusable)?;
    let policy_version = row
        .policy_version
        .map(PolicyVersion::new)
        .transpose()
        .map_err(unusable)?;
    let receipt = ChangeReceipt::new(change_id, actor, target, entity_version, policy_version);
    match row.revoked_assignments {
        Some(count) => Ok(receipt.with_revoked_assignments(
            u32::try_from(count).map_err(|error| RepositoryError::Unavailable(Box::new(error)))?,
        )),
        None => Ok(receipt),
    }
}

#[async_trait::async_trait]
impl ChangeReceiptRepository for PgChangeReceiptRepository {
    async fn find(&self, change_id: ChangeId) -> Result<ChangeReceipt, RepositoryError> {
        self.select(change_id).await
    }
}

#[cfg(test)]
mod tests;
