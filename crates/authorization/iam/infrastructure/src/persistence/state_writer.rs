//! The policy state rows of a versioned transaction: the full new state of each changed entity,
//! the running digest and the `__head` row, written into the outbox in the transaction of the
//! change (FR-70).
//!
//! The state of an entity is read from the tables of the system of record before the statements of
//! the change run and again after they ran, so the digest moves by exactly what the transaction
//! changed. The reads are checked at run time, so the offline query metadata does not hold them.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use iam_domain::{
    AssignmentScope, AssignmentState, CatalogueEntryState, CatalogueLayout, ChangeStatement,
    EntityVersion, GrantState, InvalidIamValue, LogEpoch, PolicyDigestValue, PolicyState,
    PolicyVersion, ProjectId, RatePolicyId, RatePolicyState, RepositoryError, RoleId, RoleKind,
    RoleState, RouteId, RouteState, ServiceName, StateBatch, StateChange, StateKey, StateRow,
    SubjectRef, SubjectState, UpstreamName, UpstreamState,
};
use sha2::{Digest as _, Sha256};
use shared_domain::Uuid;
use sqlx::postgres::PgRow;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;
use sqlx::{PgConnection, Row as _};

use crate::persistence::rate_policy;
use crate::persistence::role::translate;
use crate::persistence::route;
use crate::persistence::upstream;
use crate::policy_state::json_state_record_codec::JsonStateRecordCodec;
use crate::policy_state::sha256_policy_digest::Sha256PolicyDigest;

/// The topic of the policy state records.
pub const POLICY_TOPIC: &str = "iam.policy.state.v1";

/// The number of nanoseconds in one microsecond.
const NANOS_PER_MICRO: i128 = 1_000;

type States = BTreeMap<StateKey, PolicyState>;

/// Where a versioned transaction writes its rows.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Versioned {
    /// The policy version of the transaction.
    pub(crate) version: PolicyVersion,
    /// The log epoch of the policy epoch row.
    pub(crate) log_epoch: LogEpoch,
    /// When the change happened.
    pub(crate) changed_at: OffsetDateTime,
}

/// The entities that the statements of a change may change, with their state before the change.
#[derive(Debug)]
pub(crate) struct StateCapture {
    keys: BTreeSet<StateKey>,
    services: BTreeSet<ServiceName>,
    before: States,
}

impl StateCapture {
    /// Reads the state that the entities of `statements` have before the statements run.
    pub(crate) async fn before(
        connection: &mut PgConnection,
        statements: &[ChangeStatement],
    ) -> Result<Self, RepositoryError> {
        let keys: BTreeSet<StateKey> = statements
            .iter()
            .flat_map(ChangeStatement::state_keys)
            .collect();
        let services: BTreeSet<ServiceName> = statements
            .iter()
            .filter_map(ChangeStatement::catalogue_service)
            .cloned()
            .collect();
        let before = read_all(connection, &keys, &services).await?;
        Ok(Self {
            keys,
            services,
            before,
        })
    }

    /// Reads the state after the statements ran, writes the state rows and the `__head` row of the
    /// version and stores the new digest.
    pub(crate) async fn write(
        self,
        connection: &mut PgConnection,
        target: &Versioned,
    ) -> Result<(), RepositoryError> {
        let after = read_all(connection, &self.keys, &self.services).await?;
        let keys: BTreeSet<&StateKey> = self.before.keys().chain(after.keys()).collect();
        let changes = keys.into_iter().map(|key| StateChange {
            key: key.clone(),
            before: self.before.get(key).cloned(),
            after: after.get(key).cloned(),
        });
        let batch = StateBatch::assemble(
            target.version,
            read_digest(connection).await?,
            changes,
            (&JsonStateRecordCodec, &Sha256PolicyDigest),
        )
        .map_err(unusable)?;
        for row in batch.rows() {
            insert_row(connection, row, target).await?;
        }
        store_digest(connection, batch.digest()).await
    }
}

/// The state of the entities of `keys` that exist, and the catalogue records of `services`, as the
/// tables hold them now; the catalogue epoch is the one the table holds now.
async fn read_all(
    connection: &mut PgConnection,
    keys: &BTreeSet<StateKey>,
    services: &BTreeSet<ServiceName>,
) -> Result<States, RepositoryError> {
    let mut states = States::new();
    let entities = keys
        .iter()
        .filter_map(|key| entity(key).map(|entity| (key, entity)));
    for (key, entity) in entities {
        if let Some(state) = read_entity(connection, entity).await? {
            states.insert(key.clone(), state);
        }
    }
    if !services.is_empty() {
        let epoch = read_catalog_epoch(connection).await?;
        for service in services {
            let entries = read_entries(connection, service).await?;
            let layout = CatalogueLayout::build(
                service,
                epoch,
                entries,
                (&JsonStateRecordCodec, &Sha256PolicyDigest),
            )
            .map_err(unusable)?;
            states.extend(layout.states().iter().cloned());
        }
    }
    Ok(states)
}

/// An entity whose state a versioned transaction writes: a role, a subject, an upstream, a route or
/// a rate policy; no other kind of entity is written from these tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Entity<'key> {
    /// A role with its grants.
    Role(RoleId),
    /// The assignments of a subject.
    Subject(&'key SubjectRef),
    /// An upstream, named by its record key.
    Upstream(&'key UpstreamName),
    /// A route with its rate policies.
    Route(RouteId),
    /// A rate policy.
    RatePolicy(RatePolicyId),
}

/// The entity of `key`, or `None` for a key whose state is not written from these tables.
const fn entity(key: &StateKey) -> Option<Entity<'_>> {
    match key {
        StateKey::Role(id) => Some(Entity::Role(*id)),
        StateKey::Subject(subject) => Some(Entity::Subject(subject)),
        StateKey::Upstream(name) => Some(Entity::Upstream(name)),
        StateKey::Route(id) => Some(Entity::Route(*id)),
        StateKey::RatePolicy(id) => Some(Entity::RatePolicy(*id)),
        StateKey::CatalogueManifest(_)
        | StateKey::CatalogueChunk { .. }
        | StateKey::SessionRevocation(_)
        | StateKey::UserRevocation(_)
        | StateKey::GlobalRevocation
        | StateKey::Head => None,
    }
}

/// The state of one entity.
async fn read_entity(
    connection: &mut PgConnection,
    entity: Entity<'_>,
) -> Result<Option<PolicyState>, RepositoryError> {
    match entity {
        Entity::Role(id) => read_role(connection, id).await,
        Entity::Subject(subject) => read_subject(connection, subject).await,
        Entity::Upstream(name) => Ok(upstream::select_by_name(connection, name)
            .await?
            .map(|parts| PolicyState::Upstream(UpstreamState::of(&parts)))),
        Entity::Route(id) => Ok(route::select_by_id(connection, id)
            .await?
            .map(|parts| PolicyState::Route(RouteState::of(&parts)))),
        Entity::RatePolicy(id) => Ok(rate_policy::select_by_id(connection, id)
            .await?
            .map(|parts| PolicyState::RatePolicy(RatePolicyState::of(&parts)))),
    }
}

/// The role with its grants, or `None` when it is unknown or deleted.
async fn read_role(
    connection: &mut PgConnection,
    id: RoleId,
) -> Result<Option<PolicyState>, RepositoryError> {
    let uuid = id.as_uuid().as_uuid();
    let Some(row) = sqlx::query(
        "SELECT name, description, kind, version FROM iam_roles
        WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(uuid)
    .fetch_optional(&mut *connection)
    .await
    .map_err(translate)?
    else {
        return Ok(None);
    };
    let grants = sqlx::query(
        "SELECT permission_key, active FROM iam_role_permissions WHERE role_id = $1
        ORDER BY permission_key",
    )
    .bind(uuid)
    .fetch_all(&mut *connection)
    .await
    .map_err(translate)?;
    let kind: String = row.try_get("kind").map_err(translate)?;
    let version: i64 = row.try_get("version").map_err(translate)?;
    Ok(Some(PolicyState::Role(
        RoleState {
            id,
            name: row.try_get("name").map_err(translate)?,
            description: row.try_get("description").map_err(translate)?,
            kind: RoleKind::parse(&kind).map_err(unusable)?,
            version: EntityVersion::new(version).map_err(unusable)?,
            grants: grants.iter().map(grant_of).collect::<Result<_, _>>()?,
        }
        .canonical(),
    )))
}

fn grant_of(row: &PgRow) -> Result<GrantState, RepositoryError> {
    Ok(GrantState {
        key: row.try_get("permission_key").map_err(translate)?,
        active: row.try_get("active").map_err(translate)?,
    })
}

/// The assignments of the subject that are not revoked, or `None` when it has none.
async fn read_subject(
    connection: &mut PgConnection,
    subject: &SubjectRef,
) -> Result<Option<PolicyState>, RepositoryError> {
    let rows = sqlx::query(
        "SELECT role_id, scope_kind, project_id, expires_at FROM iam_user_roles
        WHERE subject_kind = $1 AND subject_id = $2 AND revoked_at IS NULL",
    )
    .bind(subject.kind().as_str())
    .bind(subject.id().to_string())
    .fetch_all(&mut *connection)
    .await
    .map_err(translate)?;
    if rows.is_empty() {
        return Ok(None);
    }
    let assignments = rows
        .iter()
        .map(assignment_of)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(PolicyState::Subject(
        SubjectState {
            subject: subject.clone(),
            assignments,
        }
        .canonical(),
    )))
}

fn assignment_of(row: &PgRow) -> Result<AssignmentState, RepositoryError> {
    let role: SqlUuid = row.try_get("role_id").map_err(translate)?;
    let scope_kind: String = row.try_get("scope_kind").map_err(translate)?;
    let project: Option<SqlUuid> = row.try_get("project_id").map_err(translate)?;
    let expires_at: Option<OffsetDateTime> = row.try_get("expires_at").map_err(translate)?;
    let project = project.map(|id| ProjectId::from_uuid(Uuid::from_uuid(id)));
    Ok(AssignmentState {
        role: RoleId::from_uuid(Uuid::from_uuid(role)),
        scope: AssignmentScope::from_parts(&scope_kind, project).map_err(unusable)?,
        expires_at_micros: expires_at.map(micros).transpose()?,
    })
}

/// The active entries of the catalogue of `service`, of both forms.
async fn read_entries(
    connection: &mut PgConnection,
    service: &ServiceName,
) -> Result<Vec<CatalogueEntryState>, RepositoryError> {
    sqlx::query(
        "SELECT permission_key, sensitive, audit_always FROM iam_rest_permissions
        WHERE service = $1 AND active
        UNION ALL
        SELECT permission_key, sensitive, audit_always FROM iam_graphql_permissions
        WHERE service = $1 AND active",
    )
    .bind(service.as_str())
    .fetch_all(&mut *connection)
    .await
    .map_err(translate)?
    .iter()
    .map(entry_of)
    .collect()
}

fn entry_of(row: &PgRow) -> Result<CatalogueEntryState, RepositoryError> {
    Ok(CatalogueEntryState {
        key: row.try_get("permission_key").map_err(translate)?,
        sensitive: row.try_get("sensitive").map_err(translate)?,
        audit_always: row.try_get("audit_always").map_err(translate)?,
    })
}

async fn read_catalog_epoch(connection: &mut PgConnection) -> Result<i64, RepositoryError> {
    sqlx::query_scalar::<_, i64>("SELECT catalog_epoch FROM iam_policy_epoch WHERE id = 1")
        .fetch_one(&mut *connection)
        .await
        .map_err(translate)
}

async fn read_digest(connection: &mut PgConnection) -> Result<PolicyDigestValue, RepositoryError> {
    let bytes =
        sqlx::query_scalar::<_, Vec<u8>>("SELECT digest FROM iam_policy_epoch WHERE id = 1")
            .fetch_one(&mut *connection)
            .await
            .map_err(translate)?;
    PolicyDigestValue::new(&bytes).map_err(unusable)
}

/// Stores the digest that the version ends with in the policy epoch row the transaction locked.
async fn store_digest(
    connection: &mut PgConnection,
    digest: PolicyDigestValue,
) -> Result<(), RepositoryError> {
    sqlx::query("UPDATE iam_policy_epoch SET digest = $1 WHERE id = 1")
        .bind(digest.as_bytes().to_vec())
        .execute(&mut *connection)
        .await
        .map(|_done| ())
        .map_err(translate)
}

/// The identifier of a state row: a hash of its place in the log, so that no generator is needed
/// and no two rows share one.
fn row_id(log_epoch: LogEpoch, version: PolicyVersion, seq: u32) -> SqlUuid {
    let hash = Sha256::digest(
        format!("iam-state/{}/{}/{seq}", log_epoch.value(), version.value()).as_bytes(),
    );
    SqlUuid::from_bytes(std::array::from_fn(|index| {
        hash.get(index).copied().unwrap_or_default()
    }))
}

/// Inserts one unpublished state row of `iam.policy.state.v1`.
async fn insert_row(
    connection: &mut PgConnection,
    row: &StateRow,
    target: &Versioned,
) -> Result<(), RepositoryError> {
    let seq = i32::try_from(row.seq()).ok().ok_or_else(out_of_range)?;
    let count = i32::try_from(row.count()).ok().ok_or_else(out_of_range)?;
    sqlx::query(
        "INSERT INTO iam_outbox (id, kind, topic, record_key, payload, policy_version, seq, count,
            digest_after, log_epoch, occurred_at)
        VALUES ($1, 'state', $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(row_id(target.log_epoch, target.version, row.seq()))
    .bind(POLICY_TOPIC)
    .bind(row.key().to_string())
    .bind(row.payload())
    .bind(target.version.value())
    .bind(seq)
    .bind(count)
    .bind(row.digest_after().as_bytes().to_vec())
    .bind(target.log_epoch.value())
    .bind(target.changed_at)
    .execute(&mut *connection)
    .await
    .map(|_done| ())
    .map_err(translate)
}

/// A time in microseconds since 1970.
fn micros(time: OffsetDateTime) -> Result<i64, RepositoryError> {
    i64::try_from(time.unix_timestamp_nanos() / NANOS_PER_MICRO)
        .ok()
        .ok_or_else(out_of_range)
}

/// A value outside the range of its column.
fn out_of_range() -> RepositoryError {
    RepositoryError::Unavailable(Box::new(InvalidIamValue::AuditTimestamp))
}

/// A stored value that breaks a domain invariant is unusable data.
fn unusable<E>(error: E) -> RepositoryError
where
    E: Error + Send + Sync + 'static,
{
    RepositoryError::Unavailable(Box::new(error))
}

#[cfg(test)]
mod tests;
