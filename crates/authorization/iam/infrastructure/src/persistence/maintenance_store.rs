//! PostgreSQL implementation of the maintenance store port.
//!
//! It finds the orphaned grants that are old enough to purge, removes the expired records and
//! writes the anchoring of the audit chain into the outbox. The statements are checked at run
//! time, so the offline metadata does not hold them.

use std::time::SystemTime;

use iam_domain::{
    AnchorStamp, AuditChainHead, AuditHash, EventEnvelope, ExpiredOrphanedGrant,
    InvalidEventEnvelope, InvalidIamValue, LogEpoch, MaintenanceStore, PermissionGrant,
    PolicyVersion, PurgedRecords, RepositoryError, RetentionCutoffs, RoleId, SecurityAuditAnchored,
};
use shared_domain::Uuid;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;
use sqlx::{PgConnection, Row as _};

use crate::persistence::event_encoding::encode;
use crate::persistence::unit_of_work::EVENTS_TOPIC;

/// Reads and removes what the maintenance task keeps small.
#[derive(Debug)]
pub struct PgMaintenanceStore {
    pool: sqlx::PgPool,
}

/// Inactive grants of roles that are not deleted whose orphaning lies before the instant.
const SELECT_ORPHANS: &str = "SELECT grants.role_id, grants.permission_key, grants.orphaned_at
    FROM iam_role_permissions AS grants
    JOIN iam_roles AS roles ON roles.id = grants.role_id
    WHERE roles.deleted_at IS NULL AND NOT grants.active AND grants.orphaned_at < $1
    ORDER BY grants.orphaned_at, grants.role_id, grants.permission_key
    LIMIT $2";

const DELETE_IDEMPOTENCY_KEYS: &str = "DELETE FROM iam_idempotency_keys WHERE created_at < $1";

const DELETE_CHANGE_RECEIPTS: &str = "DELETE FROM iam_change_receipts WHERE created_at < $1";

const DELETE_INBOUND_EVENTS: &str = "DELETE FROM iam_inbound_events WHERE processed_at < $1";

/// The head is read under a share lock, so a record that is being appended is waited for.
const SELECT_HEAD: &str =
    "SELECT seq, hash FROM iam_security_audit_chain_head WHERE id = 1 FOR SHARE";

const SELECT_EPOCH: &str = "SELECT version, log_epoch FROM iam_policy_epoch WHERE id = 1";

const INSERT_ANCHOR: &str = "INSERT INTO iam_outbox (id, kind, topic, record_key, payload,
        policy_version, log_epoch, event_type, aggregate_id, occurred_at)
    VALUES ($1, 'event', $2, $3, $4, $5, $6, $7, $3, $8)";

impl PgMaintenanceStore {
    /// Builds the store over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    async fn select_orphans(
        &self,
        orphaned_before: SystemTime,
        limit: u32,
    ) -> Result<Vec<ExpiredOrphanedGrant>, RepositoryError> {
        let rows = sqlx::query(SELECT_ORPHANS)
            .bind(OffsetDateTime::from(orphaned_before))
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await
            .map_err(unavailable)?;
        rows.iter()
            .map(|row| {
                let role_id: SqlUuid = row.try_get(0).map_err(unavailable)?;
                let key: String = row.try_get(1).map_err(unavailable)?;
                let orphaned_at: OffsetDateTime = row.try_get(2).map_err(unavailable)?;
                restore_orphan(role_id, &key, orphaned_at)
            })
            .collect()
    }

    async fn delete_expired(
        &self,
        cutoffs: &RetentionCutoffs,
    ) -> Result<PurgedRecords, RepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(unavailable)?;
        let purged = PurgedRecords {
            idempotency_records: delete_before(
                &mut transaction,
                DELETE_IDEMPOTENCY_KEYS,
                cutoffs.idempotency_records,
            )
            .await?,
            change_receipts: delete_before(
                &mut transaction,
                DELETE_CHANGE_RECEIPTS,
                cutoffs.change_receipts,
            )
            .await?,
            inbound_events: delete_before(
                &mut transaction,
                DELETE_INBOUND_EVENTS,
                cutoffs.inbound_events,
            )
            .await?,
        };
        transaction.commit().await.map_err(unavailable)?;
        Ok(purged)
    }

    async fn anchor(&self, stamp: AnchorStamp) -> Result<AuditChainHead, RepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(unavailable)?;
        let head = read_head(&mut transaction).await?;
        let (version, log_epoch) = read_epoch(&mut transaction).await?;
        let envelope =
            EventEnvelope::of(&SecurityAuditAnchored::new(stamp, head)).map_err(unencodable)?;
        let row = AnchorRow {
            id: stamp.event_id.as_uuid(),
            payload: encode(&envelope, version).map_err(unencodable)?,
            event_type: envelope.parts().event_type.as_str().to_owned(),
            aggregate_id: stamp.event_id,
            policy_version: version.value(),
            log_epoch: log_epoch.value(),
            occurred_at: OffsetDateTime::from(stamp.occurred_at),
        };
        insert_anchor(&mut transaction, &row).await?;
        transaction.commit().await.map_err(translate)?;
        Ok(head)
    }
}

/// The column values of the outbox row of one anchoring; they never leave this module.
struct AnchorRow {
    id: SqlUuid,
    payload: String,
    event_type: String,
    aggregate_id: Uuid,
    policy_version: i64,
    log_epoch: i64,
    occurred_at: OffsetDateTime,
}

/// Deletes the rows of one statement older than the cut-off; the number of rows it removed.
async fn delete_before(
    connection: &mut PgConnection,
    statement: &'static str,
    cutoff: SystemTime,
) -> Result<u64, RepositoryError> {
    sqlx::query(statement)
        .bind(OffsetDateTime::from(cutoff))
        .execute(&mut *connection)
        .await
        .map(|done| done.rows_affected())
        .map_err(unavailable)
}

/// The newest link of the audit chain, under a share lock until the end of the transaction.
async fn read_head(connection: &mut PgConnection) -> Result<AuditChainHead, RepositoryError> {
    let row = sqlx::query(SELECT_HEAD)
        .fetch_one(&mut *connection)
        .await
        .map_err(unavailable)?;
    let seq: i64 = row.try_get(0).map_err(unavailable)?;
    let hash: Vec<u8> = row.try_get(1).map_err(unavailable)?;
    restore_head(seq, &hash)
}

/// The policy version and the log epoch that the outbox row is stamped with.
async fn read_epoch(
    connection: &mut PgConnection,
) -> Result<(PolicyVersion, LogEpoch), RepositoryError> {
    let row = sqlx::query(SELECT_EPOCH)
        .fetch_one(&mut *connection)
        .await
        .map_err(unavailable)?;
    let version: i64 = row.try_get(0).map_err(unavailable)?;
    let log_epoch: i64 = row.try_get(1).map_err(unavailable)?;
    restore_epoch(version, log_epoch)
}

/// Inserts the unpublished outbox event row of the anchoring.
async fn insert_anchor(
    connection: &mut PgConnection,
    row: &AnchorRow,
) -> Result<(), RepositoryError> {
    sqlx::query(INSERT_ANCHOR)
        .bind(row.id)
        .bind(EVENTS_TOPIC)
        .bind(row.aggregate_id.to_string())
        .bind(&row.payload)
        .bind(row.policy_version)
        .bind(row.log_epoch)
        .bind(&row.event_type)
        .bind(row.occurred_at)
        .execute(&mut *connection)
        .await
        .map(|_done| ())
        .map_err(translate)
}

/// Rebuilds one orphaned grant of a stored row; a key that is no grant is unusable data.
fn restore_orphan(
    role_id: SqlUuid,
    key: &str,
    orphaned_at: OffsetDateTime,
) -> Result<ExpiredOrphanedGrant, RepositoryError> {
    Ok(ExpiredOrphanedGrant {
        role_id: RoleId::from_uuid(Uuid::from_uuid(role_id)),
        grant: PermissionGrant::parse(key)
            .map_err(|error| RepositoryError::Unavailable(Box::new(error)))?,
        orphaned_at: SystemTime::from(orphaned_at),
    })
}

/// Rebuilds the head of the chain of the stored row.
fn restore_head(seq: i64, hash: &[u8]) -> Result<AuditChainHead, RepositoryError> {
    let hash = AuditHash::new(hash).map_err(unusable)?;
    AuditChainHead::new(seq, hash).map_err(unusable)
}

/// Rebuilds the policy version and the log epoch of the stored row.
fn restore_epoch(
    version: i64,
    log_epoch: i64,
) -> Result<(PolicyVersion, LogEpoch), RepositoryError> {
    Ok((
        PolicyVersion::new(version).map_err(unusable)?,
        LogEpoch::new(log_epoch).map_err(unusable)?,
    ))
}

/// Any failure, a pool acquire timeout included, is an unavailable storage.
fn unavailable(error: sqlx::Error) -> RepositoryError {
    RepositoryError::Unavailable(Box::new(error))
}

/// A unique violation (an event id that is stored already) is a duplicate; everything else is an
/// unavailable storage.
fn translate(error: sqlx::Error) -> RepositoryError {
    let duplicate = error
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation);
    if duplicate {
        RepositoryError::AlreadyExists
    } else {
        unavailable(error)
    }
}

/// A stored value that breaks a domain invariant is unusable data.
fn unusable(error: InvalidIamValue) -> RepositoryError {
    RepositoryError::Unavailable(Box::new(error))
}

/// An event that cannot be encoded cannot be published.
fn unencodable(error: InvalidEventEnvelope) -> RepositoryError {
    RepositoryError::Unavailable(Box::new(error))
}

#[async_trait::async_trait]
impl MaintenanceStore for PgMaintenanceStore {
    async fn expired_orphaned_grants(
        &self,
        orphaned_before: SystemTime,
        limit: u32,
    ) -> Result<Vec<ExpiredOrphanedGrant>, RepositoryError> {
        self.select_orphans(orphaned_before, limit).await
    }

    async fn purge_expired_records(
        &self,
        cutoffs: &RetentionCutoffs,
    ) -> Result<PurgedRecords, RepositoryError> {
        self.delete_expired(cutoffs).await
    }

    async fn anchor_audit_chain(
        &self,
        stamp: AnchorStamp,
    ) -> Result<AuditChainHead, RepositoryError> {
        self.anchor(stamp).await
    }
}

#[cfg(test)]
mod tests;
