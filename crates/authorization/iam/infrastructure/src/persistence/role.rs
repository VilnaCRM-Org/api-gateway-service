//! PostgreSQL implementation of the role repository port: reads `iam_roles` and
//! `iam_role_permissions`, and runs the role statements that the unit of work contributes to a
//! change.

use std::collections::BTreeMap;
use std::time::SystemTime;

use iam_domain::{
    EntityVersion, GrantRecord, GrantStatus, InvalidIamValue, InvalidPermissionKey, InvalidRole,
    PermissionGrant, PermissionGrantSet, PermissionKey, PermissionKeyKind, RepositoryError, Role,
    RoleDescription, RoleId, RoleKind, RoleName, RolePageQuery, RoleParts, RoleRepository,
    RoleStatement, ServiceName, WildcardPattern,
};
use shared_domain::Uuid;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;
use sqlx::{PgConnection, Row as _};

/// Reads the roles that are not deleted, with their grants.
#[derive(Debug)]
pub struct PgRoleRepository {
    pool: sqlx::PgPool,
}

/// The stored role row; it never leaves this module.
struct RoleRow {
    id: SqlUuid,
    name: String,
    description: Option<String>,
    kind: String,
    version: i64,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

/// One stored grant of a role; it never leaves this module.
struct GrantRow {
    role_id: SqlUuid,
    permission_key: String,
}

impl PgRoleRepository {
    /// Builds the repository over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    async fn select_by_id(&self, id: RoleId) -> Result<Option<Role>, RepositoryError> {
        let row = sqlx::query_as!(
            RoleRow,
            "SELECT id, name, description, kind, version, created_at, updated_at
            FROM iam_roles WHERE id = $1 AND deleted_at IS NULL",
            id.as_uuid().as_uuid(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(translate)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let grants = self.select_grants(&[row.id]).await?;
        restore_all(vec![row], grants).map(|roles| roles.into_iter().next())
    }

    async fn select_page(&self, query: &RolePageQuery) -> Result<Vec<Role>, RepositoryError> {
        let rows = sqlx::query_as!(
            RoleRow,
            "SELECT id, name, description, kind, version, created_at, updated_at
            FROM iam_roles
            WHERE deleted_at IS NULL
                AND ($1::uuid IS NULL OR id > $1)
                AND ($2::text IS NULL OR starts_with(lower(name), lower($2)))
                AND ($3::text IS NULL OR kind = $3)
            ORDER BY id
            LIMIT $4",
            query.after.map(|id| id.as_uuid().as_uuid()),
            query.name_prefix.as_deref(),
            query.kind.map(RoleKind::as_str),
            i64::from(query.limit),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(translate)?;
        let ids: Vec<SqlUuid> = rows.iter().map(|row| row.id).collect();
        let grants = self.select_grants(&ids).await?;
        restore_all(rows, grants)
    }

    async fn select_grants(&self, ids: &[SqlUuid]) -> Result<Vec<GrantRow>, RepositoryError> {
        sqlx::query_as!(
            GrantRow,
            "SELECT role_id, permission_key FROM iam_role_permissions
            WHERE role_id = ANY($1::uuid[]) ORDER BY role_id, permission_key",
            ids,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(translate)
    }

    /// The grants of roles that are not deleted to exact keys of the service and the form. The
    /// statement is checked at run time, so the offline metadata does not hold it.
    async fn select_catalogue_grants(
        &self,
        service: &ServiceName,
        kind: PermissionKeyKind,
    ) -> Result<Vec<GrantRecord>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT grants.role_id, grants.permission_key, grants.active
            FROM iam_role_permissions AS grants
            JOIN iam_roles AS roles ON roles.id = grants.role_id
            WHERE roles.deleted_at IS NULL AND grants.service = $1 AND grants.key_kind = $2
                AND NOT grants.is_wildcard
            ORDER BY grants.role_id, grants.permission_key",
        )
        .bind(service.as_str())
        .bind(kind.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(translate)?;
        rows.iter().map(grant_record).collect()
    }
}

/// Runs one role statement inside the caller's transaction: the role row first, then its grants.
/// A failure leaves the rollback to the caller.
///
/// # Errors
///
/// [`RepositoryError::AlreadyExists`] when an insert meets a stored id or a name that a role that
/// is not deleted holds without regard to case, [`RepositoryError::Conflict`] when an update finds
/// no role that is not deleted at the expected version, and [`RepositoryError::Unavailable`] when
/// the storage fails or a value cannot be stored.
pub async fn save_within(
    connection: &mut PgConnection,
    statement: &RoleStatement,
) -> Result<(), RepositoryError> {
    let row = WriteRow::of(statement);
    match statement.expected() {
        None => insert_role(connection, &row).await?,
        Some(expected) => update_role(connection, &row, expected).await?,
    }
    replace_grants(connection, &row).await
}

/// The column values of one role write; they never leave this module.
struct WriteRow {
    id: SqlUuid,
    name: String,
    description: Option<String>,
    kind: &'static str,
    grant_count: i32,
    version: i64,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    deleted_at: Option<OffsetDateTime>,
    granted_by: String,
    grants: GrantColumns,
}

impl WriteRow {
    /// The column values of `statement`. A grant set holds at most
    /// [`PermissionGrantSet::MAX_GRANTS`] grants, so its count always fits the column; a count
    /// that did not would saturate and meet the `iam_roles_grant_count_check` constraint.
    fn of(statement: &RoleStatement) -> Self {
        let role = statement.role();
        Self {
            id: role.id.as_uuid().as_uuid(),
            name: role.name.as_str().to_owned(),
            description: role
                .description
                .as_ref()
                .map(|description| description.as_str().to_owned()),
            kind: role.kind.as_str(),
            grant_count: i32::try_from(role.grants.len()).unwrap_or(i32::MAX),
            version: role.version.value(),
            created_at: OffsetDateTime::from(role.created_at),
            updated_at: OffsetDateTime::from(role.updated_at),
            deleted_at: role.deleted_at.map(OffsetDateTime::from),
            granted_by: statement.actor().to_string(),
            grants: GrantColumns::of(&role.grants),
        }
    }
}

/// The grants of a role as parallel columns, in the order of the grant set.
#[derive(Default)]
struct GrantColumns {
    /// The text form of each grant.
    keys: Vec<String>,
    /// The key kind of each grant: `rest`, `gql` or `iam`.
    kinds: Vec<String>,
    /// The service segment of each grant.
    services: Vec<String>,
    /// Whether each grant is a wildcard.
    wildcards: Vec<bool>,
}

impl GrantColumns {
    /// The columns of every grant of `grants`.
    fn of(grants: &PermissionGrantSet) -> Self {
        grants.iter().fold(Self::default(), |mut columns, grant| {
            columns.keys.push(grant.to_string());
            columns.kinds.push(key_kind(grant).to_owned());
            columns.services.push(grant.service().to_string());
            columns.wildcards.push(grant.is_wildcard());
            columns
        })
    }
}

/// The stored key kind of a grant: `rest`, `gql` or `iam` for a reserved key.
const fn key_kind(grant: &PermissionGrant) -> &'static str {
    match grant {
        PermissionGrant::Key(key) => match key.kind() {
            PermissionKeyKind::Rest => "rest",
            PermissionKeyKind::Gql => "gql",
            PermissionKeyKind::Reserved => "iam",
        },
        PermissionGrant::Wildcard(
            WildcardPattern::GqlType { .. } | WildcardPattern::GqlService { .. },
        ) => "gql",
        PermissionGrant::Wildcard(
            WildcardPattern::RestMethod { .. } | WildcardPattern::RestService { .. },
        ) => "rest",
    }
}

/// Inserts the role row; a unique violation is a duplicate. The text values travel as one
/// `text[]` parameter in the order name and kind, the numbers as one `bigint[]` in the order grant
/// count and version, and the times as one `timestamptz[]` in the order created at and updated at,
/// which keeps the parameter list short.
async fn insert_role(connection: &mut PgConnection, row: &WriteRow) -> Result<(), RepositoryError> {
    let texts = [row.name.clone(), row.kind.to_owned()];
    let numbers = [i64::from(row.grant_count), row.version];
    let times = [row.created_at, row.updated_at];
    sqlx::query!(
        "INSERT INTO iam_roles (id, name, description, kind, grant_count, version, created_at,
            updated_at, deleted_at)
        VALUES ($1, ($2::text[])[1], $3, ($2::text[])[2], ($4::bigint[])[1], ($4::bigint[])[2],
            ($5::timestamptz[])[1], ($5::timestamptz[])[2], $6)",
        row.id,
        texts.as_slice(),
        row.description,
        numbers.as_slice(),
        times.as_slice(),
        row.deleted_at,
    )
    .execute(&mut *connection)
    .await
    .map(|_done| ())
    .map_err(translate)
}

/// Updates the role row when it is not deleted and holds the expected version. The numbers travel
/// as one `bigint[]` parameter in the order grant count, new version and expected version.
async fn update_role(
    connection: &mut PgConnection,
    row: &WriteRow,
    expected: EntityVersion,
) -> Result<(), RepositoryError> {
    let numbers = [i64::from(row.grant_count), row.version, expected.value()];
    let written = sqlx::query!(
        "UPDATE iam_roles SET name = $2, description = $3, grant_count = ($4::bigint[])[1],
            version = ($4::bigint[])[2], updated_at = $5, deleted_at = $6
        WHERE id = $1 AND version = ($4::bigint[])[3] AND deleted_at IS NULL",
        row.id,
        row.name,
        row.description,
        numbers.as_slice(),
        row.updated_at,
        row.deleted_at,
    )
    .execute(&mut *connection)
    .await
    .map_err(translate)?;
    updated(written.rows_affected())
}

/// No affected row means the stored role is unknown, deleted or at another version: a conflict.
pub(crate) const fn updated(rows_affected: u64) -> Result<(), RepositoryError> {
    if rows_affected == 0 {
        Err(RepositoryError::Conflict)
    } else {
        Ok(())
    }
}

/// Removes the grants the role no longer holds and adds the new ones; a grant the role keeps
/// keeps its original grantor and time.
async fn replace_grants(
    connection: &mut PgConnection,
    row: &WriteRow,
) -> Result<(), RepositoryError> {
    delete_dropped_grants(connection, row).await?;
    insert_added_grants(connection, row).await
}

/// Deletes the grants of the role that the written grant set no longer holds.
async fn delete_dropped_grants(
    connection: &mut PgConnection,
    row: &WriteRow,
) -> Result<(), RepositoryError> {
    sqlx::query!(
        "DELETE FROM iam_role_permissions
        WHERE role_id = $1 AND NOT (permission_key = ANY($2::text[]))",
        row.id,
        row.grants.keys.as_slice(),
    )
    .execute(&mut *connection)
    .await
    .map(|_done| ())
    .map_err(translate)
}

/// Inserts the grants the role does not hold yet. A new grant is granted at the `updated_at` of
/// the role row, which the same transaction has just written with the time of this change.
async fn insert_added_grants(
    connection: &mut PgConnection,
    row: &WriteRow,
) -> Result<(), RepositoryError> {
    let grants = &row.grants;
    sqlx::query!(
        "INSERT INTO iam_role_permissions (role_id, permission_key, key_kind, service, is_wildcard,
            active, granted_by, granted_at)
        SELECT role.id, grant_row.permission_key, grant_row.key_kind, grant_row.service,
            grant_row.is_wildcard, TRUE, $6, role.updated_at
        FROM iam_roles role,
            UNNEST($2::text[], $3::text[], $4::text[], $5::bool[])
                AS grant_row (permission_key, key_kind, service, is_wildcard)
        WHERE role.id = $1
        ON CONFLICT (role_id, permission_key) DO NOTHING",
        row.id,
        grants.keys.as_slice(),
        grants.kinds.as_slice(),
        grants.services.as_slice(),
        grants.wildcards.as_slice(),
        row.granted_by,
    )
    .execute(&mut *connection)
    .await
    .map(|_done| ())
    .map_err(translate)
}

/// Rebuilds the roles of `rows`, in their order, with the grants of `grants`.
fn restore_all(rows: Vec<RoleRow>, grants: Vec<GrantRow>) -> Result<Vec<Role>, RepositoryError> {
    let mut by_role: BTreeMap<SqlUuid, Vec<String>> = BTreeMap::new();
    for grant in grants {
        by_role
            .entry(grant.role_id)
            .or_default()
            .push(grant.permission_key);
    }
    rows.into_iter()
        .map(|row| {
            let keys = by_role.remove(&row.id).unwrap_or_default();
            restore(row, &keys)
        })
        .collect()
}

/// Rebuilds one stored role through the value objects.
fn restore(row: RoleRow, keys: &[String]) -> Result<Role, RepositoryError> {
    Ok(Role::restore(RoleParts {
        id: RoleId::from_uuid(Uuid::from_uuid(row.id)),
        name: RoleName::new(row.name).map_err(invalid_role)?,
        description: row
            .description
            .map(RoleDescription::new)
            .transpose()
            .map_err(invalid_role)?,
        kind: RoleKind::parse(&row.kind).map_err(invalid_role)?,
        grants: restore_grants(keys)?,
        version: EntityVersion::new(row.version).map_err(unusable)?,
        created_at: SystemTime::from(row.created_at),
        updated_at: SystemTime::from(row.updated_at),
        deleted_at: None,
    }))
}

/// Rebuilds the grant set of the stored keys; a stored key that is not a grant, or too many keys,
/// is unusable data.
fn restore_grants(keys: &[String]) -> Result<PermissionGrantSet, RepositoryError> {
    let grants = keys
        .iter()
        .map(|key| PermissionGrant::parse(key))
        .collect::<Result<Vec<_>, InvalidPermissionKey>>()
        .map_err(invalid_key)?;
    PermissionGrantSet::new(grants).map_err(unusable)
}

/// A unique violation (a stored id or a name in use) is a duplicate; everything else is an
/// unavailable repository.
pub(crate) fn translate(error: sqlx::Error) -> RepositoryError {
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

/// A stored role field that breaks a domain invariant is unusable data.
fn invalid_role(error: InvalidRole) -> RepositoryError {
    RepositoryError::Unavailable(Box::new(error))
}

/// A stored grant that is not a permission key or a wildcard is unusable data.
fn invalid_key(error: InvalidPermissionKey) -> RepositoryError {
    RepositoryError::Unavailable(Box::new(error))
}

/// The catalogue grant that a stored row holds.
fn grant_record(row: &sqlx::postgres::PgRow) -> Result<GrantRecord, RepositoryError> {
    let role_id: SqlUuid = row.try_get("role_id").map_err(translate)?;
    let permission_key: String = row.try_get("permission_key").map_err(translate)?;
    let active: bool = row.try_get("active").map_err(translate)?;
    Ok(GrantRecord {
        role: RoleId::from_uuid(Uuid::from_uuid(role_id)),
        key: PermissionKey::parse(&permission_key).map_err(invalid_key)?,
        status: if active {
            GrantStatus::Active
        } else {
            GrantStatus::Orphaned
        },
    })
}

#[async_trait::async_trait]
impl RoleRepository for PgRoleRepository {
    async fn find_by_id(&self, id: RoleId) -> Result<Option<Role>, RepositoryError> {
        self.select_by_id(id).await
    }

    async fn find_page(&self, query: &RolePageQuery) -> Result<Vec<Role>, RepositoryError> {
        self.select_page(query).await
    }

    async fn find_catalogue_grants(
        &self,
        service: &ServiceName,
        kind: PermissionKeyKind,
    ) -> Result<Vec<GrantRecord>, RepositoryError> {
        self.select_catalogue_grants(service, kind).await
    }
}

#[cfg(test)]
mod tests;
