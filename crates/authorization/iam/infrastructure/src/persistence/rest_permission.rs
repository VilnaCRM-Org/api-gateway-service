//! PostgreSQL implementation of the REST permission repository port: reads
//! `iam_rest_permissions`, and runs the catalogue writes of an activation that the unit of work
//! contributes to a change.

use iam_domain::{
    CatalogueStatementParts, EntryFlags, EntryInsert, HttpMethod, InvalidCatalogueEntry,
    InvalidPermissionKey, PermissionFlags, PermissionId, PermissionKey, PermissionPageQuery,
    RepositoryError, RestPermission, RestPermissionParts, RestPermissionRepository, ServiceName,
};
use shared_domain::Uuid;
use sqlx::PgConnection;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;

use crate::persistence::catalogue::{expect_rows, state_filter, translate_entry};
use crate::persistence::openapi_spec::transition_within;
use crate::persistence::role::translate;

/// Reads the stored REST catalogue entries.
#[derive(Debug)]
pub struct PgRestPermissionRepository {
    pool: sqlx::PgPool,
}

/// A stored value that cannot be turned back into a catalogue entry.
#[derive(Debug, thiserror::Error)]
enum UnusablePermissionRow {
    /// The stored key is not a permission key.
    #[error("a stored permission key is invalid")]
    Key(#[source] InvalidPermissionKey),
    /// The stored key is not a REST key.
    #[error("a stored permission is not a REST entry")]
    Entry(#[source] InvalidCatalogueEntry),
}

/// The stored entry row; it never leaves this module.
struct PermissionRow {
    id: SqlUuid,
    permission_key: String,
    sensitive: bool,
    audit_always: bool,
    active: Activity,
}

/// Whether a stored entry is active: the `active` column, decoded apart from the flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(transparent)]
struct Activity(bool);

impl PgRestPermissionRepository {
    /// Builds the repository over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    async fn select_by_id(
        &self,
        id: PermissionId,
    ) -> Result<Option<RestPermission>, RepositoryError> {
        let row = sqlx::query_as!(
            PermissionRow,
            "SELECT id, permission_key, sensitive, audit_always, active AS \"active: Activity\"
            FROM iam_rest_permissions WHERE id = $1",
            id.as_uuid().as_uuid(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(translate)?;
        row.as_ref().map(restore).transpose()
    }

    async fn select_by_keys(
        &self,
        service: &ServiceName,
        keys: &[PermissionKey],
    ) -> Result<Vec<RestPermission>, RepositoryError> {
        let keys: Vec<String> = keys.iter().map(PermissionKey::to_string).collect();
        let rows = sqlx::query_as!(
            PermissionRow,
            "SELECT id, permission_key, sensitive, audit_always, active AS \"active: Activity\"
            FROM iam_rest_permissions
            WHERE service = $1 AND permission_key = ANY($2)
            ORDER BY permission_key",
            service.as_str(),
            keys.as_slice(),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(translate)?;
        restore_all(&rows)
    }

    async fn select_by_service(
        &self,
        service: &ServiceName,
    ) -> Result<Vec<RestPermission>, RepositoryError> {
        let rows = sqlx::query_as!(
            PermissionRow,
            "SELECT id, permission_key, sensitive, audit_always, active AS \"active: Activity\"
            FROM iam_rest_permissions WHERE service = $1 ORDER BY permission_key",
            service.as_str(),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(translate)?;
        restore_all(&rows)
    }

    async fn select_page(
        &self,
        query: &PermissionPageQuery,
    ) -> Result<Vec<RestPermission>, RepositoryError> {
        let states = state_filter(query.active, query.sensitive);
        let rows = sqlx::query_as!(
            PermissionRow,
            "SELECT id, permission_key, sensitive, audit_always, active AS \"active: Activity\"
            FROM iam_rest_permissions
            WHERE ($1::uuid IS NULL OR id > $1)
                AND ($2::text IS NULL OR service = $2)
                AND (active::text || ':' || sensitive::text) = ANY($3::text[])
                AND ($4::text IS NULL OR starts_with(permission_key, $4))
                AND ($5::text IS NULL OR method = $5)
            ORDER BY id
            LIMIT $6",
            query.after.map(|id| id.as_uuid().as_uuid()),
            query.service.as_ref().map(ServiceName::as_str),
            states.as_slice(),
            query.key_prefix.as_deref(),
            query.method.map(HttpMethod::as_str),
            i64::from(query.limit),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(translate)?;
        restore_all(&rows)
    }
}

/// Runs the writes of one activation or retirement against the REST tables.
///
/// The writes run inside the caller's transaction: the status of the version, the new entries and
/// their flags, the changed flags and the entries that become active or inactive. A failure leaves
/// the rollback to the caller.
///
/// # Errors
///
/// [`RepositoryError::Conflict`] when the version is no longer in the expected status, an entry
/// the change was decided against is gone or a created key is stored already, and
/// [`RepositoryError::Unavailable`] when the storage fails.
pub async fn write_within(
    connection: &mut PgConnection,
    parts: &CatalogueStatementParts,
) -> Result<(), RepositoryError> {
    transition_within(connection, &parts.transition).await?;
    let created = EntryColumns::of(&parts.created);
    insert_entries(connection, parts, &created).await?;
    update_flags(connection, &created.flags).await?;
    update_flags(connection, &FlagColumns::of(&parts.reflagged)).await?;
    set_active(connection, &parts.service, &parts.reactivated, true).await?;
    set_active(connection, &parts.service, &parts.deactivated, false).await
}

/// The entries to insert as parallel columns, one element per entry.
#[derive(Debug, Default, PartialEq, Eq)]
struct EntryColumns {
    ids: Vec<SqlUuid>,
    keys: Vec<String>,
    methods: Vec<String>,
    templates: Vec<String>,
    flags: FlagColumns,
}

impl EntryColumns {
    /// The columns of the REST `entries`; an entry of another form cannot be part of a validated
    /// statement and has no operation to store.
    fn of(entries: &[EntryInsert]) -> Self {
        let mut columns = Self::default();
        for entry in entries {
            let PermissionKey::Rest {
                method, template, ..
            } = &entry.key
            else {
                continue;
            };
            columns.ids.push(entry.id.as_uuid().as_uuid());
            columns.keys.push(entry.key.to_string());
            columns.methods.push(method.to_string());
            columns.templates.push(template.to_string());
            columns.flags.push(&entry.key, entry.flags);
        }
        columns
    }
}

/// The new flags as parallel columns, one element per entry.
#[derive(Debug, Default, PartialEq, Eq)]
struct FlagColumns {
    keys: Vec<String>,
    sensitive: Vec<bool>,
    audit_always: Vec<bool>,
}

impl FlagColumns {
    fn of(changes: &[EntryFlags]) -> Self {
        let mut columns = Self::default();
        for change in changes {
            columns.push(&change.key, change.flags);
        }
        columns
    }

    /// Appends the flags of one entry.
    fn push(&mut self, key: &PermissionKey, flags: PermissionFlags) {
        self.keys.push(key.to_string());
        self.sensitive.push(flags.is_sensitive());
        self.audit_always.push(flags.is_audit_always());
    }
}

/// Inserts the new entries, active and without flags, with the time of the change; their flags
/// are set by [`update_flags`] in the same transaction.
async fn insert_entries(
    connection: &mut PgConnection,
    parts: &CatalogueStatementParts,
    columns: &EntryColumns,
) -> Result<(), RepositoryError> {
    sqlx::query!(
        "INSERT INTO iam_rest_permissions (id, permission_key, service, method, path_template,
            sensitive, audit_always, active, created_at)
        SELECT id, permission_key, $5::text, method, path_template, FALSE, FALSE, TRUE,
            $6::timestamptz
        FROM UNNEST($1::uuid[], $2::text[], $3::text[], $4::text[])
            AS entries (id, permission_key, method, path_template)",
        columns.ids.as_slice(),
        columns.keys.as_slice(),
        columns.methods.as_slice(),
        columns.templates.as_slice(),
        parts.service.as_str(),
        OffsetDateTime::from(parts.at),
    )
    .execute(&mut *connection)
    .await
    .map(|_done| ())
    .map_err(translate_entry)
}

/// Sets the flags of the stored entries.
async fn update_flags(
    connection: &mut PgConnection,
    columns: &FlagColumns,
) -> Result<(), RepositoryError> {
    let written = sqlx::query!(
        "UPDATE iam_rest_permissions AS entries
        SET sensitive = changed.sensitive, audit_always = changed.audit_always
        FROM UNNEST($1::text[], $2::bool[], $3::bool[])
            AS changed (permission_key, sensitive, audit_always)
        WHERE entries.permission_key = changed.permission_key",
        columns.keys.as_slice(),
        columns.sensitive.as_slice(),
        columns.audit_always.as_slice(),
    )
    .execute(&mut *connection)
    .await
    .map_err(translate)?;
    expect_rows(written.rows_affected(), columns.keys.len())
}

/// Marks the stored entries of the keys active or inactive.
async fn set_active(
    connection: &mut PgConnection,
    service: &ServiceName,
    keys: &[PermissionKey],
    active: bool,
) -> Result<(), RepositoryError> {
    let keys: Vec<String> = keys.iter().map(PermissionKey::to_string).collect();
    let written = sqlx::query!(
        "UPDATE iam_rest_permissions SET active = $1
        WHERE service = $2 AND permission_key = ANY($3)",
        active,
        service.as_str(),
        keys.as_slice(),
    )
    .execute(&mut *connection)
    .await
    .map_err(translate)?;
    expect_rows(written.rows_affected(), keys.len())
}

/// A stored value that cannot be rebuilt is unusable data.
fn unusable(error: UnusablePermissionRow) -> RepositoryError {
    RepositoryError::Unavailable(Box::new(error))
}

/// Rebuilds one stored entry through the value objects.
fn restore(row: &PermissionRow) -> Result<RestPermission, RepositoryError> {
    let key = PermissionKey::parse(&row.permission_key)
        .map_err(|error| unusable(UnusablePermissionRow::Key(error)))?;
    let mut flags = PermissionFlags::NONE;
    if row.sensitive {
        flags = flags.with_sensitive();
    }
    if row.audit_always {
        flags = flags.with_audit_always();
    }
    RestPermission::restore(RestPermissionParts {
        id: PermissionId::from_uuid(Uuid::from_uuid(row.id)),
        key,
        flags,
        active: row.active.0,
    })
    .map_err(|error| unusable(UnusablePermissionRow::Entry(error)))
}

/// Rebuilds the entries of `rows`, in their order.
fn restore_all(rows: &[PermissionRow]) -> Result<Vec<RestPermission>, RepositoryError> {
    rows.iter().map(restore).collect()
}

#[async_trait::async_trait]
impl RestPermissionRepository for PgRestPermissionRepository {
    async fn find_by_id(
        &self,
        id: PermissionId,
    ) -> Result<Option<RestPermission>, RepositoryError> {
        self.select_by_id(id).await
    }

    async fn find_by_keys(
        &self,
        service: &ServiceName,
        keys: &[PermissionKey],
    ) -> Result<Vec<RestPermission>, RepositoryError> {
        self.select_by_keys(service, keys).await
    }

    async fn find_by_service(
        &self,
        service: &ServiceName,
    ) -> Result<Vec<RestPermission>, RepositoryError> {
        self.select_by_service(service).await
    }

    async fn find_page(
        &self,
        query: &PermissionPageQuery,
    ) -> Result<Vec<RestPermission>, RepositoryError> {
        self.select_page(query).await
    }
}

#[cfg(test)]
mod tests;
