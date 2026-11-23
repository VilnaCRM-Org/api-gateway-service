//! PostgreSQL implementation of the unit of work: one transaction per administrative change.
//!
//! A versioned transaction writes one outbox state row for every entity it changed, the policy
//! digest and the `__head` row of its version, next to the outbox event rows; Story 7.4 adds the
//! relay wake-up.

use std::time::SystemTime;

use iam_domain::{
    ChangeReceipt, ChangeStatement, EventEnvelope, IamChange, IamUnitOfWork, IdempotencyRecord,
    InvalidEventEnvelope, InvalidIamValue, LogEpoch, PolicyVersion, RepositoryError,
    StoredSecurityAuditEvent,
};
use sqlx::PgConnection;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;

use crate::persistence::catalogue;
use crate::persistence::event_encoding::encode;
use crate::persistence::graphql_spec;
use crate::persistence::openapi_spec;
use crate::persistence::role::save_within;
use crate::persistence::security_audit_log::{PgSecurityAuditLog, emit};
use crate::persistence::state_writer::{StateCapture, Versioned};
use crate::persistence::user_role;

/// The topic of the IAM domain events.
pub const EVENTS_TOPIC: &str = "iam.events.v1";

/// The number of nanoseconds in one microsecond.
const NANOS_PER_MICRO: i128 = 1_000;

/// Commits administrative changes in one transaction.
///
/// It writes the `iam_policy_epoch` (the version, the digest and the catalogue epoch), the state
/// and event rows of `iam_outbox`, `iam_security_audit_events`,
/// `iam_change_receipts` and `iam_idempotency_keys` tables, and runs the role statements against
/// `iam_roles` and `iam_role_permissions`, the assignment statements against `iam_user_roles` and
/// the specification statements against `iam_graphql_specs`, `iam_graphql_spec_fields` and
/// `iam_graphql_spec_possible_types`, and the `OpenAPI` specification statements against
/// `iam_openapi_specs` and `iam_openapi_spec_operations`, and the catalogue statements against
/// `iam_graphql_permissions`, `iam_rest_permissions`, `iam_role_permissions` and the catalogue epoch
/// of `iam_policy_epoch`, together with the status of the activated version.
#[derive(Debug)]
pub struct PgIamUnitOfWork {
    pool: sqlx::PgPool,
}

/// The locked policy epoch row; it never leaves this module.
struct EpochRow {
    version: i64,
    log_epoch: i64,
}

/// The policy version and log epoch that the transaction locked.
struct Locked {
    version: PolicyVersion,
    log_epoch: LogEpoch,
}

impl PgIamUnitOfWork {
    /// Builds the unit of work over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    async fn commit_change(&self, change: &IamChange) -> Result<ChangeReceipt, RepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(translate)?;
        let (version, stored) = write(&mut transaction, change).await?;
        transaction.commit().await.map_err(translate)?;
        stored.iter().for_each(emit);
        Ok(change.receipt(version))
    }
}

/// Writes the whole change inside the caller's transaction and returns the policy version of the
/// transaction and the appended audit records. A failure leaves the rollback to the caller.
async fn write(
    connection: &mut PgConnection,
    change: &IamChange,
) -> Result<(PolicyVersion, Vec<StoredSecurityAuditEvent>), RepositoryError> {
    let changed_at = timestamp(change.occurred_at_micros())?;
    let locked = lock_epoch(connection).await?;
    let version = next_version(connection, change, &locked, changed_at).await?;
    check(&change.parts().statements, locked.version)?;
    let capture = capture_state(connection, change).await?;
    run(connection, &change.parts().statements).await?;
    if let Some(capture) = capture {
        let target = Versioned {
            version,
            log_epoch: locked.log_epoch,
            changed_at,
        };
        capture.write(connection, &target).await?;
    }
    let stored = write_records(connection, change, version, locked.log_epoch, changed_at).await?;
    Ok((version, stored))
}

/// The state of the entities that a change affecting decisions may change, before its statements
/// run; a change that does not affect decisions writes no state row.
async fn capture_state(
    connection: &mut PgConnection,
    change: &IamChange,
) -> Result<Option<StateCapture>, RepositoryError> {
    if change.affects_decisions() {
        StateCapture::before(connection, &change.parts().statements)
            .await
            .map(Some)
    } else {
        Ok(None)
    }
}

/// The policy version of the transaction: the next one when the change affects decisions, the
/// locked one otherwise.
async fn next_version(
    connection: &mut PgConnection,
    change: &IamChange,
    locked: &Locked,
    changed_at: OffsetDateTime,
) -> Result<PolicyVersion, RepositoryError> {
    if change.affects_decisions() {
        increment(connection, changed_at).await
    } else {
        Ok(locked.version)
    }
}

/// Writes the outbox event rows, the audit record, the change receipt and the idempotency record.
async fn write_records(
    connection: &mut PgConnection,
    change: &IamChange,
    version: PolicyVersion,
    log_epoch: LogEpoch,
    changed_at: OffsetDateTime,
) -> Result<Vec<StoredSecurityAuditEvent>, RepositoryError> {
    for envelope in &change.parts().events {
        insert_event(connection, &EventRow::of(envelope, version, log_epoch)?).await?;
    }
    let stored = PgSecurityAuditLog::append_within(connection, &change.audits(version)).await?;
    insert_receipt(
        connection,
        &ReceiptRow::of(&change.receipt(version), changed_at),
    )
    .await?;
    if let Some(record) = change.idempotency_record() {
        insert_idempotency(connection, &KeyRow::of(&record, changed_at)).await?;
    }
    Ok(stored)
}

/// Locks the single policy epoch row until the end of the transaction.
async fn lock_epoch(connection: &mut PgConnection) -> Result<Locked, RepositoryError> {
    let row = sqlx::query_as!(
        EpochRow,
        "SELECT version, log_epoch FROM iam_policy_epoch WHERE id = 1 FOR UPDATE",
    )
    .fetch_one(&mut *connection)
    .await
    .map_err(translate)?;
    restore(&row)
}

/// Takes the next policy version under the row lock.
async fn increment(
    connection: &mut PgConnection,
    changed_at: OffsetDateTime,
) -> Result<PolicyVersion, RepositoryError> {
    let version = sqlx::query_scalar!(
        "UPDATE iam_policy_epoch SET version = version + 1, updated_at = $1 WHERE id = 1 RETURNING version",
        changed_at,
    )
    .fetch_one(&mut *connection)
    .await
    .map_err(translate)?;
    PolicyVersion::new(version).map_err(unusable)
}

/// Refuses the change with a conflict when one of its statements does not hold under the locked
/// policy version.
fn check(statements: &[ChangeStatement], locked: PolicyVersion) -> Result<(), RepositoryError> {
    if statements.iter().all(|statement| statement.holds(locked)) {
        Ok(())
    } else {
        Err(RepositoryError::Conflict)
    }
}

/// Runs the aggregate writes of the statements, in order; a guard writes nothing.
async fn run(
    connection: &mut PgConnection,
    statements: &[ChangeStatement],
) -> Result<(), RepositoryError> {
    for statement in statements {
        match statement {
            ChangeStatement::ExpectPolicyVersion(_) => {}
            ChangeStatement::SaveRole(role) => save_within(connection, role).await?,
            ChangeStatement::SaveUserRole(assignment) => {
                user_role::save_within(connection, assignment).await?;
            }
            ChangeStatement::SaveGraphQlSpec(version) => {
                graphql_spec::save_within(connection, version).await?;
            }
            ChangeStatement::SaveOpenApiSpec(version) => {
                openapi_spec::save_within(connection, version).await?;
            }
            ChangeStatement::ApplyCatalogue(activation) => {
                catalogue::apply_within(connection, activation).await?;
            }
        }
    }
    Ok(())
}

/// The column values of one outbox event row; they never leave this module.
struct EventRow {
    id: SqlUuid,
    record_key: String,
    payload: String,
    policy_version: i64,
    log_epoch: i64,
    event_type: String,
    occurred_at: OffsetDateTime,
}

impl EventRow {
    /// The row of `envelope` in a transaction at `version`, keyed by the aggregate id.
    fn of(
        envelope: &EventEnvelope,
        version: PolicyVersion,
        log_epoch: LogEpoch,
    ) -> Result<Self, RepositoryError> {
        let parts = envelope.parts();
        Ok(Self {
            id: parts.id.as_uuid(),
            record_key: parts.aggregate_id.to_string(),
            payload: encode(envelope, version).map_err(unencodable)?,
            policy_version: version.value(),
            log_epoch: log_epoch.value(),
            event_type: parts.event_type.as_str().to_owned(),
            occurred_at: timestamp(envelope.occurred_at_micros())?,
        })
    }
}

/// Inserts one unpublished event row of `iam.events.v1`. The text values travel as one `text[]`
/// parameter in the order topic, record key, payload and event type, and the numbers as one
/// `bigint[]` in the order policy version and log epoch, which keeps the parameter list short; the
/// record key is also the aggregate id.
async fn insert_event(
    connection: &mut PgConnection,
    row: &EventRow,
) -> Result<(), RepositoryError> {
    let texts = [
        EVENTS_TOPIC.to_owned(),
        row.record_key.clone(),
        row.payload.clone(),
        row.event_type.clone(),
    ];
    let numbers = [row.policy_version, row.log_epoch];
    sqlx::query!(
        "INSERT INTO iam_outbox (id, kind, topic, record_key, payload, policy_version, log_epoch,
            event_type, aggregate_id, occurred_at)
        VALUES ($1, 'event', ($2::text[])[1], ($2::text[])[2], ($2::text[])[3],
            ($3::bigint[])[1], ($3::bigint[])[2], ($2::text[])[4], ($2::text[])[2], $4)",
        row.id,
        texts.as_slice(),
        numbers.as_slice(),
        row.occurred_at,
    )
    .execute(&mut *connection)
    .await
    .map(|_done| ())
    .map_err(translate)
}

/// The column values of one change receipt; they never leave this module.
struct ReceiptRow {
    change_id: SqlUuid,
    actor: String,
    target_type: String,
    target_id: String,
    entity_version: i64,
    policy_version: Option<i64>,
    revoked_assignments: Option<i32>,
    created_at: OffsetDateTime,
}

impl ReceiptRow {
    fn of(receipt: &ChangeReceipt, created_at: OffsetDateTime) -> Self {
        Self {
            change_id: receipt.change_id().as_uuid().as_uuid(),
            actor: receipt.actor().to_string(),
            target_type: receipt.target().target_type().to_owned(),
            target_id: receipt.target().target_id().to_owned(),
            entity_version: receipt.entity_version().value(),
            policy_version: receipt.policy_version().map(PolicyVersion::value),
            revoked_assignments: receipt
                .revoked_assignments()
                .map(|count| i32::try_from(count).unwrap_or(i32::MAX)),
            created_at,
        }
    }
}

/// Inserts the change receipt. The text values travel as one `text[]` parameter in the order
/// actor, target type and target id.
async fn insert_receipt(
    connection: &mut PgConnection,
    row: &ReceiptRow,
) -> Result<(), RepositoryError> {
    let texts = [
        row.actor.clone(),
        row.target_type.clone(),
        row.target_id.clone(),
    ];
    sqlx::query!(
        "INSERT INTO iam_change_receipts (change_id, actor, target_type, target_id, entity_version,
            policy_version, revoked_assignments, created_at)
        VALUES ($1, ($2::text[])[1], ($2::text[])[2], ($2::text[])[3], $3, $4, $5, $6)",
        row.change_id,
        texts.as_slice(),
        row.entity_version,
        row.policy_version,
        row.revoked_assignments,
        row.created_at,
    )
    .execute(&mut *connection)
    .await
    .map(|_done| ())
    .map_err(translate)
}

/// The column values of one idempotency record; they never leave this module.
struct KeyRow {
    actor: String,
    key: String,
    request_digest: Vec<u8>,
    change_id: SqlUuid,
    created_at: OffsetDateTime,
    expired_before: OffsetDateTime,
}

impl KeyRow {
    /// The row of `record` created at `created_at`; a stored record of the same key created
    /// before `expired_before` is expired.
    fn of(record: &IdempotencyRecord, created_at: OffsetDateTime) -> Self {
        Self {
            actor: record.actor().to_string(),
            key: record.key().as_str().to_owned(),
            request_digest: record.request_digest().as_bytes().to_vec(),
            change_id: record.change_id().as_uuid().as_uuid(),
            created_at,
            expired_before: window_start(created_at),
        }
    }
}

/// The oldest creation time of a record that still replays at `created_at`, by the domain rule
/// [`IdempotencyRecord::window_start`].
fn window_start(created_at: OffsetDateTime) -> OffsetDateTime {
    OffsetDateTime::from(IdempotencyRecord::window_start(SystemTime::from(
        created_at,
    )))
}

/// Inserts the idempotency record, or replaces an expired record of the same key; a key the actor
/// used within the replay window is a duplicate.
async fn insert_idempotency(
    connection: &mut PgConnection,
    row: &KeyRow,
) -> Result<(), RepositoryError> {
    let written = sqlx::query!(
        "INSERT INTO iam_idempotency_keys (actor, idempotency_key, request_digest, change_id,
            created_at)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (actor, idempotency_key) DO UPDATE
        SET request_digest = EXCLUDED.request_digest, change_id = EXCLUDED.change_id,
            created_at = EXCLUDED.created_at
        WHERE iam_idempotency_keys.created_at < $6",
        row.actor,
        row.key,
        row.request_digest,
        row.change_id,
        row.created_at,
        row.expired_before,
    )
    .execute(&mut *connection)
    .await
    .map_err(translate)?;
    inserted_or_replaced(written.rows_affected())
}

/// No affected row means the key holds a record within the replay window: a duplicate.
const fn inserted_or_replaced(rows_affected: u64) -> Result<(), RepositoryError> {
    if rows_affected == 0 {
        Err(RepositoryError::AlreadyExists)
    } else {
        Ok(())
    }
}

/// The `timestamptz` value of a time in microseconds since 1970.
fn timestamp(micros: i64) -> Result<OffsetDateTime, RepositoryError> {
    i128::from(micros)
        .checked_mul(NANOS_PER_MICRO)
        .and_then(|nanos| OffsetDateTime::from_unix_timestamp_nanos(nanos).ok())
        .ok_or_else(out_of_range)
}

/// A time after the year 9999 cannot be stored.
fn out_of_range() -> RepositoryError {
    RepositoryError::Unavailable(Box::new(InvalidIamValue::AuditTimestamp))
}

/// Rebuilds the locked values through the value objects.
fn restore(row: &EpochRow) -> Result<Locked, RepositoryError> {
    Ok(Locked {
        version: PolicyVersion::new(row.version).map_err(unusable)?,
        log_epoch: LogEpoch::new(row.log_epoch).map_err(unusable)?,
    })
}

/// A unique violation (a stored change id, event id or idempotency key) is a duplicate; everything
/// else, a missing policy epoch row included, is an unavailable repository.
fn translate(error: sqlx::Error) -> RepositoryError {
    let duplicate = error
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation);
    if duplicate {
        RepositoryError::AlreadyExists
    } else {
        RepositoryError::Unavailable(Box::new(error))
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
impl IamUnitOfWork for PgIamUnitOfWork {
    async fn commit(&self, change: IamChange) -> Result<ChangeReceipt, RepositoryError> {
        self.commit_change(&change).await
    }
}

#[cfg(test)]
mod tests;
