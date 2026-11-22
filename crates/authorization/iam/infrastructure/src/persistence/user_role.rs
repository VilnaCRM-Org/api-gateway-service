//! PostgreSQL implementation of the assignment repository port: reads `iam_user_roles`, and runs
//! the assignment statements that the unit of work contributes to a change.

use std::time::SystemTime;

use iam_domain::{
    ActorRef, AssignmentExpiry, AssignmentScope, EntityVersion, InvalidIamValue, ProjectId,
    RepositoryError, RoleId, SubjectKind, SubjectRef, UserRole, UserRoleId, UserRolePageQuery,
    UserRoleParts, UserRoleRepository, UserRoleStatement,
};
use shared_domain::Uuid;
use sqlx::PgConnection;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;

use crate::persistence::role::{translate, updated};

/// Reads the assignments that are not revoked.
#[derive(Debug)]
pub struct PgUserRoleRepository {
    pool: sqlx::PgPool,
}

/// The stored assignment row; it never leaves this module.
struct UserRoleRow {
    id: SqlUuid,
    subject_kind: String,
    subject_id: String,
    role_id: SqlUuid,
    scope_kind: String,
    project_id: Option<SqlUuid>,
    expires_at: Option<OffsetDateTime>,
    version: i64,
    created_by: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl PgUserRoleRepository {
    /// Builds the repository over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    async fn select_by_id(&self, id: UserRoleId) -> Result<Option<UserRole>, RepositoryError> {
        let row = sqlx::query_as!(
            UserRoleRow,
            "SELECT id, subject_kind, subject_id, role_id, scope_kind, project_id, expires_at,
                version, created_by, created_at, updated_at
            FROM iam_user_roles WHERE id = $1 AND revoked_at IS NULL",
            id.as_uuid().as_uuid(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(translate)?;
        row.as_ref().map(restore).transpose()
    }

    /// Reads one page. The subject filters travel as one `text[]` parameter: the subject kind
    /// first, empty when absent (no kind is empty), then the subject id only when present, so that
    /// a missing element reads as `NULL`. An expiry cutoff of `NULL` lists expired assignments too.
    async fn select_page(
        &self,
        query: &UserRolePageQuery,
    ) -> Result<Vec<UserRole>, RepositoryError> {
        let subject: Vec<String> = std::iter::once(
            query
                .subject_kind
                .map_or("", SubjectKind::as_str)
                .to_owned(),
        )
        .chain(query.subject_id.clone())
        .collect();
        let cutoff = (!query.include_expired).then(|| OffsetDateTime::from(query.now));
        let rows = sqlx::query_as!(
            UserRoleRow,
            "SELECT id, subject_kind, subject_id, role_id, scope_kind, project_id, expires_at,
                version, created_by, created_at, updated_at
            FROM iam_user_roles
            WHERE revoked_at IS NULL
                AND ($1::uuid IS NULL OR id > $1)
                AND (($2::text[])[1] = '' OR subject_kind = ($2::text[])[1])
                AND (($2::text[])[2] IS NULL OR subject_id = ($2::text[])[2])
                AND ($3::uuid IS NULL OR role_id = $3)
                AND ($4::uuid IS NULL OR project_id = $4)
                AND ($5::timestamptz IS NULL OR expires_at IS NULL OR expires_at > $5)
            ORDER BY id
            LIMIT $6",
            query.after.map(|id| id.as_uuid().as_uuid()),
            subject.as_slice(),
            query.role_id.map(|id| id.as_uuid().as_uuid()),
            query.project_id.map(|id| id.as_uuid().as_uuid()),
            cutoff,
            i64::from(query.limit),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(translate)?;
        rows.iter().map(restore).collect()
    }
}

/// Runs one assignment statement inside the caller's transaction. A failure leaves the rollback to
/// the caller.
///
/// # Errors
///
/// [`RepositoryError::AlreadyExists`] when an insert meets a stored id or an assignment that is
/// not revoked with the same subject, role and scope, [`RepositoryError::Conflict`] when an update
/// finds no assignment that is not revoked at the expected version, and
/// [`RepositoryError::Unavailable`] when the storage fails or a value cannot be stored.
pub async fn save_within(
    connection: &mut PgConnection,
    statement: &UserRoleStatement,
) -> Result<(), RepositoryError> {
    let row = WriteRow::of(statement.user_role());
    match statement.expected() {
        None => insert(connection, &row).await,
        Some(expected) => update(connection, &row, expected).await,
    }
}

/// The column values of one assignment write; they never leave this module.
#[derive(Debug, PartialEq, Eq)]
struct WriteRow {
    id: SqlUuid,
    subject_kind: &'static str,
    subject_id: String,
    role_id: SqlUuid,
    scope_kind: &'static str,
    project_id: Option<SqlUuid>,
    expires_at: Option<OffsetDateTime>,
    version: i64,
    created_by: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
}

impl WriteRow {
    /// The column values of `user_role`.
    fn of(user_role: &UserRoleParts) -> Self {
        Self {
            id: user_role.id.as_uuid().as_uuid(),
            subject_kind: user_role.subject.kind().as_str(),
            subject_id: user_role.subject.id().to_string(),
            role_id: user_role.role_id.as_uuid().as_uuid(),
            scope_kind: user_role.scope.kind(),
            project_id: user_role
                .scope
                .project_id()
                .map(|id| id.as_uuid().as_uuid()),
            expires_at: user_role
                .expires_at
                .map(|expiry| OffsetDateTime::from(expiry.at())),
            version: user_role.version.value(),
            created_by: user_role.created_by.to_string(),
            created_at: OffsetDateTime::from(user_role.created_at),
            updated_at: OffsetDateTime::from(user_role.updated_at),
            revoked_at: user_role.revoked_at.map(OffsetDateTime::from),
        }
    }
}

/// Inserts the assignment row; a unique violation is a duplicate.
///
/// The identifiers travel as one `uuid[]` parameter in the order id, role id and, only for a
/// project scope, project id, so that a missing project id reads as `NULL`; the text values as one
/// `text[]` in the order subject kind, subject id, scope kind and creator; and the times as one
/// `timestamptz[]` in the order created at and updated at, which keeps the parameter list short.
async fn insert(connection: &mut PgConnection, row: &WriteRow) -> Result<(), RepositoryError> {
    let ids: Vec<SqlUuid> = [row.id, row.role_id]
        .into_iter()
        .chain(row.project_id)
        .collect();
    let texts = [
        row.subject_kind.to_owned(),
        row.subject_id.clone(),
        row.scope_kind.to_owned(),
        row.created_by.clone(),
    ];
    let times = [row.created_at, row.updated_at];
    sqlx::query!(
        "INSERT INTO iam_user_roles (id, subject_kind, subject_id, role_id, scope_kind, project_id,
            expires_at, version, created_by, created_at, updated_at, revoked_at)
        VALUES (($1::uuid[])[1], ($2::text[])[1], ($2::text[])[2], ($1::uuid[])[2],
            ($2::text[])[3], ($1::uuid[])[3], $3, $4, ($2::text[])[4], ($5::timestamptz[])[1],
            ($5::timestamptz[])[2], $6)",
        ids.as_slice(),
        texts.as_slice(),
        row.expires_at,
        row.version,
        times.as_slice(),
        row.revoked_at,
    )
    .execute(&mut *connection)
    .await
    .map(|_done| ())
    .map_err(translate)
}

/// Updates the expiry, the version, the change time and the revocation of the assignment row when
/// it is not revoked and holds the expected version.
async fn update(
    connection: &mut PgConnection,
    row: &WriteRow,
    expected: EntityVersion,
) -> Result<(), RepositoryError> {
    let written = sqlx::query!(
        "UPDATE iam_user_roles SET expires_at = $2, version = $3, updated_at = $4, revoked_at = $5
        WHERE id = $1 AND version = $6 AND revoked_at IS NULL",
        row.id,
        row.expires_at,
        row.version,
        row.updated_at,
        row.revoked_at,
        expected.value(),
    )
    .execute(&mut *connection)
    .await
    .map_err(translate)?;
    updated(written.rows_affected())
}

/// Rebuilds one stored assignment through the value objects; a value that breaks an invariant is
/// unusable data.
fn restore(row: &UserRoleRow) -> Result<UserRole, RepositoryError> {
    let kind = SubjectKind::parse(&row.subject_kind).map_err(unusable)?;
    let project_id = row
        .project_id
        .map(|id| ProjectId::from_uuid(Uuid::from_uuid(id)));
    Ok(UserRole::restore(UserRoleParts {
        id: UserRoleId::from_uuid(Uuid::from_uuid(row.id)),
        subject: SubjectRef::new(kind, &row.subject_id).map_err(unusable)?,
        role_id: RoleId::from_uuid(Uuid::from_uuid(row.role_id)),
        scope: AssignmentScope::from_parts(&row.scope_kind, project_id).map_err(unusable)?,
        expires_at: row
            .expires_at
            .map(|at| AssignmentExpiry::restore(SystemTime::from(at))),
        version: EntityVersion::new(row.version).map_err(unusable)?,
        created_by: ActorRef::parse(&row.created_by).map_err(unusable)?,
        created_at: SystemTime::from(row.created_at),
        updated_at: SystemTime::from(row.updated_at),
        revoked_at: None,
    }))
}

/// A stored value that breaks a domain invariant is unusable data.
fn unusable(error: InvalidIamValue) -> RepositoryError {
    RepositoryError::Unavailable(Box::new(error))
}

#[async_trait::async_trait]
impl UserRoleRepository for PgUserRoleRepository {
    async fn find_by_id(&self, id: UserRoleId) -> Result<Option<UserRole>, RepositoryError> {
        self.select_by_id(id).await
    }

    async fn find_page(&self, query: &UserRolePageQuery) -> Result<Vec<UserRole>, RepositoryError> {
        self.select_page(query).await
    }
}

#[cfg(test)]
mod tests;
