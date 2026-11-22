//! PostgreSQL implementation of the security audit log port.
//!
//! The hash chain is extended in SQL under the lock of the chain-head row, and every appended
//! record is also emitted as a `tracing` event with target `audit`.

use iam_domain::{
    ActorRef, AssignmentScope, AuditAction, AuditChainHead, AuditHash, AuditOutcome, AuditReason,
    AuditSummary, AuditTarget, IdempotencyKey, InvalidIamValue, PolicyVersion, RepositoryError,
    RequestId, SecurityAuditEvent, SecurityAuditEventId, SecurityAuditEventParts, SecurityAuditLog,
    ServiceName, StoredSecurityAuditEvent,
};
use shared_domain::Uuid;
use sqlx::PgConnection;
use sqlx::types::Uuid as SqlUuid;

/// The message of the `tracing` event of an appended record.
const AUDIT_MESSAGE: &str = "security audit event";

/// The append-only, hash-chained `iam_security_audit_events` table.
#[derive(Debug)]
pub struct PgSecurityAuditLog {
    pool: sqlx::PgPool,
}

/// The chain-head row; it never leaves this module.
struct HeadRow {
    seq: i64,
    hash: Vec<u8>,
}

/// A stored record; it never leaves this module.
struct Row {
    seq: i64,
    id: SqlUuid,
    occurred_at_micros: i64,
    actor: String,
    caller_service: Option<String>,
    action: String,
    target_type: String,
    target_id: String,
    scope: Option<String>,
    before_summary: Option<String>,
    after_summary: Option<String>,
    idempotency_key: Option<String>,
    outcome: String,
    reason: Option<String>,
    policy_version: Option<i64>,
    request_id: Option<String>,
    prev_hash: Vec<u8>,
    hash: Vec<u8>,
}

impl PgSecurityAuditLog {
    /// Builds the log over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// Appends the records in order inside the caller's transaction: locks the chain-head row,
    /// inserts every record with `hash = sha256(prev_hash || canonical_form)` computed in SQL and
    /// moves the head. The caller commits, then calls [`emit`] for each returned record.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::AlreadyExists`] when a record id is already stored, and
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    pub async fn append_within(
        connection: &mut PgConnection,
        events: &[SecurityAuditEvent],
    ) -> Result<Vec<StoredSecurityAuditEvent>, RepositoryError> {
        let locked = sqlx::query_as!(
            HeadRow,
            "SELECT seq, hash FROM iam_security_audit_chain_head WHERE id = 1 FOR UPDATE",
        )
        .fetch_one(&mut *connection)
        .await
        .map_err(unavailable)?;
        let mut head = restore_head(&locked)?;
        let mut stored = Vec::with_capacity(events.len());
        for event in events {
            let record = insert(connection, event, head.hash()).await?;
            head = AuditChainHead::new(record.seq(), record.hash()).map_err(unusable)?;
            stored.push(record);
        }
        Ok(stored)
    }

    async fn append_committed(
        &self,
        events: &[SecurityAuditEvent],
    ) -> Result<AuditChainHead, RepositoryError> {
        if events.is_empty() {
            return self.select_head().await;
        }
        let mut transaction = self.pool.begin().await.map_err(translate)?;
        let stored = Self::append_within(&mut transaction, events).await?;
        transaction.commit().await.map_err(translate)?;
        stored.iter().for_each(emit);
        let newest = stored.last().ok_or(RepositoryError::NotFound)?;
        AuditChainHead::new(newest.seq(), newest.hash()).map_err(unusable)
    }

    async fn select_head(&self) -> Result<AuditChainHead, RepositoryError> {
        let row = sqlx::query_as!(
            HeadRow,
            "SELECT seq, hash FROM iam_security_audit_chain_head WHERE id = 1",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(unavailable)?;
        restore_head(&row)
    }

    async fn select_by_id(
        &self,
        id: SecurityAuditEventId,
    ) -> Result<StoredSecurityAuditEvent, RepositoryError> {
        let row = sqlx::query_as!(
            Row,
            r#"SELECT seq, id, (extract(epoch FROM occurred_at) * 1000000)::bigint AS "occurred_at_micros!",
                actor, caller_service, action, target_type, target_id, scope, before_summary,
                after_summary, idempotency_key, outcome, reason, policy_version, request_id,
                prev_hash, hash
            FROM iam_security_audit_events WHERE id = $1"#,
            id.as_uuid().as_uuid(),
        )
        .fetch_one(&self.pool)
        .await
        .map_err(translate)?;
        restore(&row)
    }

    async fn select_after(
        &self,
        after_seq: i64,
        limit: u32,
    ) -> Result<Vec<StoredSecurityAuditEvent>, RepositoryError> {
        let rows = sqlx::query_as!(
            Row,
            r#"SELECT seq, id, (extract(epoch FROM occurred_at) * 1000000)::bigint AS "occurred_at_micros!",
                actor, caller_service, action, target_type, target_id, scope, before_summary,
                after_summary, idempotency_key, outcome, reason, policy_version, request_id,
                prev_hash, hash
            FROM iam_security_audit_events WHERE seq > $1 ORDER BY seq LIMIT $2"#,
            after_seq,
            i64::from(limit),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(unavailable)?;
        rows.iter().map(restore).collect()
    }
}

/// The column values of one record. The text values travel as one `text[]` parameter, in the
/// order actor, caller service, action, target type, target id, scope, before summary, after
/// summary, idempotency key, outcome, reason, request id and canonical form, which keeps the
/// statement's parameter list short. An absent value travels as empty text, which no present
/// value can be, and is stored as `NULL`.
struct Columns {
    id: SqlUuid,
    occurred_at_micros: i64,
    texts: Vec<String>,
    policy_version: Option<i64>,
}

impl Columns {
    fn of(event: &SecurityAuditEvent) -> Self {
        let parts = event.parts();
        let texts = vec![
            parts.actor.to_string(),
            text(parts.caller_service.as_ref().map(ServiceName::as_str)),
            parts.action.to_string(),
            parts.target.target_type().to_owned(),
            parts.target.target_id().to_owned(),
            parts
                .scope
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
            text(parts.before.as_ref().map(AuditSummary::as_str)),
            text(parts.after.as_ref().map(AuditSummary::as_str)),
            text(parts.idempotency_key.as_ref().map(IdempotencyKey::as_str)),
            parts.outcome.as_str().to_owned(),
            text(parts.reason.as_ref().map(AuditReason::as_str)),
            text(parts.request_id.as_ref().map(RequestId::as_str)),
            event.canonical_form(),
        ];
        Self {
            id: parts.id.as_uuid().as_uuid(),
            occurred_at_micros: event.occurred_at_micros(),
            texts,
            policy_version: parts.policy_version.map(PolicyVersion::value),
        }
    }
}

/// An owned copy of an optional text, empty when it is absent.
fn text(value: Option<&str>) -> String {
    optional(value).to_owned()
}

/// Inserts one record after the link `prev_hash` and moves the chain head to it.
async fn insert(
    connection: &mut PgConnection,
    event: &SecurityAuditEvent,
    prev_hash: AuditHash,
) -> Result<StoredSecurityAuditEvent, RepositoryError> {
    let columns = Columns::of(event);
    let appended = sqlx::query_as!(
        HeadRow,
        r#"WITH appended AS (
            INSERT INTO iam_security_audit_events (seq, id, occurred_at, actor, caller_service,
                action, target_type, target_id, scope, before_summary, after_summary,
                idempotency_key, outcome, reason, policy_version, request_id, prev_hash, hash)
            SELECT head.seq + 1, $1,
                'epoch'::timestamptz + ($2::bigint / 1000000) * interval '1 second'
                    + ($2::bigint % 1000000) * interval '1 microsecond',
                bound.v[1], NULLIF(bound.v[2], ''), bound.v[3], bound.v[4], bound.v[5],
                NULLIF(bound.v[6], ''), NULLIF(bound.v[7], ''), NULLIF(bound.v[8], ''),
                NULLIF(bound.v[9], ''), bound.v[10], NULLIF(bound.v[11], ''), $4,
                NULLIF(bound.v[12], ''), head.hash,
                sha256(head.hash || convert_to(bound.v[13], 'UTF8'))
            FROM iam_security_audit_chain_head head, (SELECT $3::text[] AS v) bound
            WHERE head.id = 1
            RETURNING seq, hash
        )
        UPDATE iam_security_audit_chain_head SET seq = appended.seq, hash = appended.hash
        FROM appended WHERE iam_security_audit_chain_head.id = 1
        RETURNING appended.seq AS "seq!", appended.hash AS "hash!""#,
        columns.id,
        columns.occurred_at_micros,
        columns.texts.as_slice(),
        columns.policy_version,
    )
    .fetch_one(&mut *connection)
    .await
    .map_err(translate)?;
    link(&appended, event, prev_hash)
}

/// Places the inserted record in the chain from the returned sequence number and hash.
fn link(
    appended: &HeadRow,
    event: &SecurityAuditEvent,
    prev_hash: AuditHash,
) -> Result<StoredSecurityAuditEvent, RepositoryError> {
    let hash = AuditHash::new(&appended.hash).map_err(unusable)?;
    StoredSecurityAuditEvent::new(appended.seq, event.clone(), prev_hash, hash).map_err(unusable)
}

/// Emits the record as one `tracing` event with target `audit`; the JSON log layer of the service
/// renders it as one JSON object.
pub fn emit(record: &StoredSecurityAuditEvent) {
    let event = record.event();
    let parts = event.parts();
    let seq = record.seq();
    let id = parts.id;
    let occurred_at_micros = event.occurred_at_micros();
    let actor = &parts.actor;
    let caller_service = optional(parts.caller_service.as_ref().map(ServiceName::as_str));
    let action = parts.action.as_str();
    let target_type = parts.target.target_type();
    let target_id = parts.target.target_id();
    let scope = parts
        .scope
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_default();
    let before_summary = optional(parts.before.as_ref().map(AuditSummary::as_str));
    let after_summary = optional(parts.after.as_ref().map(AuditSummary::as_str));
    let idempotency_key = optional(parts.idempotency_key.as_ref().map(IdempotencyKey::as_str));
    let outcome = parts.outcome.as_str();
    let reason = optional(parts.reason.as_ref().map(AuditReason::as_str));
    let policy_version = parts
        .policy_version
        .map(|version| version.value().to_string())
        .unwrap_or_default();
    let request_id = optional(parts.request_id.as_ref().map(RequestId::as_str));
    let hash = record.hash();
    tracing::info!(target: "audit", event_name = "iam.security_audit.recorded", seq, %id, occurred_at_micros, %actor, caller_service, action, target_type, target_id, %scope, before_summary, after_summary, idempotency_key, outcome, reason, %policy_version, request_id, %hash, "{AUDIT_MESSAGE}");
}

/// The text of an optional value, empty when it is absent.
fn optional(value: Option<&str>) -> &str {
    value.unwrap_or_default()
}

/// A unique violation (a record id that is already stored) is a duplicate; everything else is an
/// unavailable repository; a query that found no row is a missing record.
fn translate(error: sqlx::Error) -> RepositoryError {
    let duplicate = error
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation);
    if duplicate {
        RepositoryError::AlreadyExists
    } else if matches!(error, sqlx::Error::RowNotFound) {
        RepositoryError::NotFound
    } else {
        RepositoryError::Unavailable(Box::new(error))
    }
}

/// Any failure, a missing chain-head row included, is an unavailable repository.
fn unavailable(error: sqlx::Error) -> RepositoryError {
    RepositoryError::Unavailable(Box::new(error))
}

/// A stored value that breaks a domain invariant is unusable data.
fn unusable(error: InvalidIamValue) -> RepositoryError {
    RepositoryError::Unavailable(Box::new(error))
}

/// Rebuilds the chain head of the stored row.
fn restore_head(row: &HeadRow) -> Result<AuditChainHead, RepositoryError> {
    let hash = AuditHash::new(&row.hash).map_err(unusable)?;
    AuditChainHead::new(row.seq, hash).map_err(unusable)
}

/// Rebuilds an optional value from its stored text.
fn parse_optional<T>(
    value: Option<&str>,
    parse: impl FnOnce(&str) -> Result<T, InvalidIamValue>,
) -> Result<Option<T>, InvalidIamValue> {
    value.map(parse).transpose()
}

/// Rebuilds the values of a stored record through the value objects.
fn restore_parts(row: &Row) -> Result<SecurityAuditEventParts, InvalidIamValue> {
    Ok(SecurityAuditEventParts {
        id: SecurityAuditEventId::from_uuid(Uuid::from_uuid(row.id)),
        occurred_at: std::time::SystemTime::UNIX_EPOCH,
        actor: ActorRef::parse(&row.actor)?,
        caller_service: parse_optional(row.caller_service.as_deref(), ServiceName::new)?,
        action: AuditAction::new(&row.action)?,
        target: AuditTarget::new(&row.target_type, &row.target_id)?,
        scope: parse_optional(row.scope.as_deref(), AssignmentScope::parse)?,
        before: parse_optional(row.before_summary.as_deref(), AuditSummary::new)?,
        after: parse_optional(row.after_summary.as_deref(), AuditSummary::new)?,
        idempotency_key: parse_optional(row.idempotency_key.as_deref(), IdempotencyKey::new)?,
        outcome: AuditOutcome::parse(&row.outcome)?,
        reason: parse_optional(row.reason.as_deref(), AuditReason::new)?,
        policy_version: row.policy_version.map(PolicyVersion::new).transpose()?,
        request_id: parse_optional(row.request_id.as_deref(), RequestId::new)?,
    })
}

/// Rebuilds a stored record with its place in the chain.
fn restore(row: &Row) -> Result<StoredSecurityAuditEvent, RepositoryError> {
    let parts = restore_parts(row).map_err(unusable)?;
    let event = SecurityAuditEvent::restore(parts, row.occurred_at_micros).map_err(unusable)?;
    let prev_hash = AuditHash::new(&row.prev_hash).map_err(unusable)?;
    let hash = AuditHash::new(&row.hash).map_err(unusable)?;
    StoredSecurityAuditEvent::new(row.seq, event, prev_hash, hash).map_err(unusable)
}

#[async_trait::async_trait]
impl SecurityAuditLog for PgSecurityAuditLog {
    async fn append_batch(
        &self,
        events: &[SecurityAuditEvent],
    ) -> Result<AuditChainHead, RepositoryError> {
        self.append_committed(events).await
    }

    async fn chain_head(&self) -> Result<AuditChainHead, RepositoryError> {
        self.select_head().await
    }

    async fn find_by_id(
        &self,
        id: SecurityAuditEventId,
    ) -> Result<StoredSecurityAuditEvent, RepositoryError> {
        self.select_by_id(id).await
    }

    async fn find_after(
        &self,
        after_seq: i64,
        limit: u32,
    ) -> Result<Vec<StoredSecurityAuditEvent>, RepositoryError> {
        self.select_after(after_seq, limit).await
    }
}

#[cfg(test)]
mod tests;
