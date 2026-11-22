//! PostgreSQL implementation of the `OpenAPI` specification repository port: reads
//! `iam_openapi_specs` with its operations, and runs the insert statement that the unit of work
//! contributes to a change.
//!
//! The document and the operations of a stored version are written once, by the insert; no
//! statement of this module updates them, and a trigger of the table refuses it too.

use std::collections::BTreeMap;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, ContentHash, HttpMethod, InvalidIamValue, InvalidSpec, OpenApiSpec,
    OpenApiSpecContent, OpenApiSpecPageQuery, OpenApiSpecParts, OpenApiSpecRepository,
    OpenApiSpecStatement, PathTemplate, PermissionFlags, RepositoryError, RestOperation,
    RestOperationSet, ServiceName, SpecId, SpecStatus,
};
use shared_domain::Uuid;
use sqlx::PgConnection;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;

use crate::persistence::role::translate;

/// Reads the stored `OpenAPI` specification versions.
#[derive(Debug)]
pub struct PgOpenApiSpecRepository {
    pool: sqlx::PgPool,
}

/// A stored value that cannot be turned back into a domain value.
#[derive(Debug, thiserror::Error)]
enum UnusableSpecRow {
    /// A stored name, hash, method, template or status is not valid.
    #[error("a stored specification value is invalid: {0}")]
    Value(&'static str),
    /// The stored operations do not make a valid operation set.
    #[error("the stored operations do not make an operation set")]
    Operations(#[source] InvalidSpec),
    /// A stored value breaks a domain invariant.
    #[error("a stored value breaks a domain invariant")]
    Invariant(#[source] InvalidIamValue),
}

/// The stored version row; it never leaves this module.
struct SpecRow {
    id: SqlUuid,
    service: String,
    content_hash: Vec<u8>,
    status: String,
    uploaded_by: String,
    created_at: OffsetDateTime,
    activated_at: Option<OffsetDateTime>,
    retired_at: Option<OffsetDateTime>,
}

/// The stored operation row; it never leaves this module.
struct OperationRow {
    spec_id: SqlUuid,
    method: String,
    path_template: String,
    label: Option<String>,
    sensitive: bool,
    audit_always: bool,
}

impl PgOpenApiSpecRepository {
    /// Builds the repository over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    async fn select_by_id(&self, id: SpecId) -> Result<Option<OpenApiSpec>, RepositoryError> {
        let rows = sqlx::query_as!(
            SpecRow,
            "SELECT id, service, content_hash, status, uploaded_by, created_at, activated_at,
                retired_at
            FROM iam_openapi_specs WHERE id = $1",
            id.as_uuid().as_uuid(),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(translate)?;
        Ok(self.restore_all(rows).await?.pop())
    }

    async fn select_document(&self, id: SpecId) -> Result<Option<String>, RepositoryError> {
        sqlx::query_scalar!(
            "SELECT document FROM iam_openapi_specs WHERE id = $1",
            id.as_uuid().as_uuid(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(translate)
    }

    async fn select_by_content_hash(
        &self,
        service: &ServiceName,
        content_hash: &ContentHash,
    ) -> Result<Option<OpenApiSpec>, RepositoryError> {
        let rows = sqlx::query_as!(
            SpecRow,
            "SELECT id, service, content_hash, status, uploaded_by, created_at, activated_at,
                retired_at
            FROM iam_openapi_specs WHERE service = $1 AND content_hash = $2",
            service.as_str(),
            content_hash.as_bytes().as_slice(),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(translate)?;
        Ok(self.restore_all(rows).await?.pop())
    }

    async fn select_active(
        &self,
        service: &ServiceName,
    ) -> Result<Vec<OpenApiSpec>, RepositoryError> {
        let rows = sqlx::query_as!(
            SpecRow,
            "SELECT id, service, content_hash, status, uploaded_by, created_at, activated_at,
                retired_at
            FROM iam_openapi_specs WHERE service = $1 AND status = 'active' ORDER BY id",
            service.as_str(),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(translate)?;
        self.restore_all(rows).await
    }

    async fn select_page(
        &self,
        query: &OpenApiSpecPageQuery,
    ) -> Result<Vec<OpenApiSpec>, RepositoryError> {
        let rows = sqlx::query_as!(
            SpecRow,
            "SELECT id, service, content_hash, status, uploaded_by, created_at, activated_at,
                retired_at
            FROM iam_openapi_specs
            WHERE ($1::uuid IS NULL OR id > $1)
                AND ($2::text IS NULL OR service = $2)
                AND ($3::text IS NULL OR status = $3)
            ORDER BY id
            LIMIT $4",
            query.after.map(|id| id.as_uuid().as_uuid()),
            query.service.as_ref().map(ServiceName::as_str),
            query.status.map(SpecStatus::as_str),
            i64::from(query.limit),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(translate)?;
        self.restore_all(rows).await
    }

    /// Rebuilds the versions of `rows` with their operations, in the order of `rows`. The content
    /// of a version never changes after the insert, so the reads need no common snapshot.
    async fn restore_all(&self, rows: Vec<SpecRow>) -> Result<Vec<OpenApiSpec>, RepositoryError> {
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<SqlUuid> = rows.iter().map(|row| row.id).collect();
        let mut operations = group(self.select_operations(&ids).await?, |row| row.spec_id);
        rows.iter()
            .map(|row| {
                let set = operation_set(&operations.remove(&row.id).unwrap_or_default())?;
                restore(row, set)
            })
            .collect()
    }

    async fn select_operations(
        &self,
        ids: &[SqlUuid],
    ) -> Result<Vec<OperationRow>, RepositoryError> {
        sqlx::query_as!(
            OperationRow,
            "SELECT spec_id, method, path_template, label, sensitive, audit_always
            FROM iam_openapi_spec_operations WHERE spec_id = ANY($1)",
            ids,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(translate)
    }
}

/// Groups `rows` by the key of each row.
fn group<R>(rows: Vec<R>, key: impl Fn(&R) -> SqlUuid) -> BTreeMap<SqlUuid, Vec<R>> {
    let mut grouped: BTreeMap<SqlUuid, Vec<R>> = BTreeMap::new();
    for row in rows {
        grouped.entry(key(&row)).or_default().push(row);
    }
    grouped
}

/// Runs one specification statement inside the caller's transaction: the version row, then its
/// labelled and its unlabelled operations. A failure leaves the rollback to the caller.
///
/// # Errors
///
/// [`RepositoryError::AlreadyExists`] when the id is stored or the service already has a version
/// with the same content hash, and [`RepositoryError::Unavailable`] when the storage fails or the
/// hash of the version is not the SHA-256 hash of its document.
pub async fn save_within(
    connection: &mut PgConnection,
    statement: &OpenApiSpecStatement,
) -> Result<(), RepositoryError> {
    let row = WriteRow::of(statement);
    insert_spec(connection, &row).await?;
    insert_labelled_operations(connection, &row).await?;
    insert_unlabelled_operations(connection, &row).await
}

/// The column values of one version write; they never leave this module.
#[derive(Debug, PartialEq, Eq)]
struct WriteRow {
    id: SqlUuid,
    service: String,
    content_hash: Vec<u8>,
    document: String,
    status: &'static str,
    uploaded_by: String,
    created_at: OffsetDateTime,
    activated_at: Option<OffsetDateTime>,
    retired_at: Option<OffsetDateTime>,
    labelled: OperationColumns,
    unlabelled: OperationColumns,
}

/// Operation rows of a version as parallel columns, one element per operation. The operations
/// with a label and those without travel apart, so the unlabelled ones store a SQL `NULL` label
/// and `labels` stays empty for them.
#[derive(Debug, Default, PartialEq, Eq)]
struct OperationColumns {
    methods: Vec<String>,
    templates: Vec<String>,
    labels: Vec<String>,
    sensitive: Vec<bool>,
    audit_always: Vec<bool>,
}

impl WriteRow {
    /// The column values of `statement`.
    fn of(statement: &OpenApiSpecStatement) -> Self {
        let spec = statement.spec();
        let mut labelled = OperationColumns::default();
        let mut unlabelled = OperationColumns::default();
        for (key, details) in spec.content.operations.iter() {
            let columns = match &details.label {
                Some(label) => {
                    labelled.labels.push(label.clone());
                    &mut labelled
                }
                None => &mut unlabelled,
            };
            columns.methods.push(key.method.to_string());
            columns.templates.push(key.template.to_string());
            columns.sensitive.push(details.flags.is_sensitive());
            columns.audit_always.push(details.flags.is_audit_always());
        }
        Self {
            id: spec.id.as_uuid().as_uuid(),
            service: spec.content.service.to_string(),
            content_hash: spec.content.content_hash.as_bytes().to_vec(),
            document: statement.document().to_owned(),
            status: spec.status.as_str(),
            uploaded_by: spec.uploaded_by.to_string(),
            created_at: OffsetDateTime::from(spec.created_at),
            activated_at: spec.activated_at.map(OffsetDateTime::from),
            retired_at: spec.retired_at.map(OffsetDateTime::from),
            labelled,
            unlabelled,
        }
    }
}

/// Inserts the version row. The hash is computed by SQL `sha256()` over the document and the row
/// is written only when it equals the hash of the version; a unique violation is a duplicate.
///
/// The text values travel as one `text[]` parameter in the order service, document, status and
/// uploader, which keeps the parameter list short.
async fn insert_spec(connection: &mut PgConnection, row: &WriteRow) -> Result<(), RepositoryError> {
    let texts = [
        row.service.clone(),
        row.document.clone(),
        row.status.to_owned(),
        row.uploaded_by.clone(),
    ];
    let written = sqlx::query!(
        "INSERT INTO iam_openapi_specs (id, service, content_hash, document, status, uploaded_by,
            created_at, activated_at, retired_at)
        SELECT $1::uuid, ($2::text[])[1], sha256(convert_to(($2::text[])[2], 'UTF8')), ($2::text[])[2],
            ($2::text[])[3], ($2::text[])[4], $3::timestamptz, $4::timestamptz, $5::timestamptz
        WHERE sha256(convert_to(($2::text[])[2], 'UTF8')) = $6",
        row.id,
        texts.as_slice(),
        row.created_at,
        row.activated_at,
        row.retired_at,
        row.content_hash.as_slice(),
    )
    .execute(&mut *connection)
    .await
    .map_err(translate)?;
    hashed(written.rows_affected())
}

/// No affected row means that the hash of the version is not the hash of its document.
fn hashed(rows_affected: u64) -> Result<(), RepositoryError> {
    if rows_affected == 0 {
        Err(RepositoryError::Unavailable(
            "the content hash is not the SHA-256 hash of the document".into(),
        ))
    } else {
        Ok(())
    }
}

/// Inserts the labelled operation rows of the version, one row per element of the columns.
async fn insert_labelled_operations(
    connection: &mut PgConnection,
    row: &WriteRow,
) -> Result<(), RepositoryError> {
    sqlx::query!(
        "INSERT INTO iam_openapi_spec_operations (spec_id, method, path_template, label,
            sensitive, audit_always)
        SELECT $1::uuid, method, path_template, label, sensitive, audit_always
        FROM UNNEST($2::text[], $3::text[], $4::text[], $5::bool[], $6::bool[])
            AS operations (method, path_template, label, sensitive, audit_always)",
        row.id,
        row.labelled.methods.as_slice(),
        row.labelled.templates.as_slice(),
        row.labelled.labels.as_slice(),
        row.labelled.sensitive.as_slice(),
        row.labelled.audit_always.as_slice(),
    )
    .execute(&mut *connection)
    .await
    .map(|_done| ())
    .map_err(translate)
}

/// Inserts the unlabelled operation rows of the version with a `NULL` label, one row per element
/// of the columns.
async fn insert_unlabelled_operations(
    connection: &mut PgConnection,
    row: &WriteRow,
) -> Result<(), RepositoryError> {
    sqlx::query!(
        "INSERT INTO iam_openapi_spec_operations (spec_id, method, path_template, label,
            sensitive, audit_always)
        SELECT $1::uuid, method, path_template, NULL, sensitive, audit_always
        FROM UNNEST($2::text[], $3::text[], $4::bool[], $5::bool[])
            AS operations (method, path_template, sensitive, audit_always)",
        row.id,
        row.unlabelled.methods.as_slice(),
        row.unlabelled.templates.as_slice(),
        row.unlabelled.sensitive.as_slice(),
        row.unlabelled.audit_always.as_slice(),
    )
    .execute(&mut *connection)
    .await
    .map(|_done| ())
    .map_err(translate)
}

/// Rebuilds the operation set of the stored operations through the value objects.
fn operation_set(rows: &[OperationRow]) -> Result<RestOperationSet, RepositoryError> {
    let mut set = RestOperationSet::new();
    for row in rows {
        set.insert(operation(row)?)
            .map_err(|error| unusable(UnusableSpecRow::Operations(error)))?;
    }
    Ok(set)
}

/// Rebuilds one stored operation.
fn operation(row: &OperationRow) -> Result<RestOperation, RepositoryError> {
    let mut flags = PermissionFlags::NONE;
    if row.sensitive {
        flags = flags.with_sensitive();
    }
    if row.audit_always {
        flags = flags.with_audit_always();
    }
    Ok(RestOperation {
        method: HttpMethod::parse(&row.method)
            .ok_or_else(|| unusable(UnusableSpecRow::Value("an HTTP method")))?,
        template: PathTemplate::from_stored(&row.path_template)
            .ok_or_else(|| unusable(UnusableSpecRow::Value("a path template")))?,
        label: row.label.clone(),
        flags,
    })
}

/// Rebuilds one stored version around its operations; a value that breaks an invariant is
/// unusable data.
fn restore(row: &SpecRow, operations: RestOperationSet) -> Result<OpenApiSpec, RepositoryError> {
    let content_hash = ContentHash::new(&row.content_hash)
        .ok_or_else(|| unusable(UnusableSpecRow::Value("a content hash")))?;
    let status = SpecStatus::parse(&row.status)
        .ok_or_else(|| unusable(UnusableSpecRow::Value("a status")))?;
    Ok(OpenApiSpec::restore(OpenApiSpecParts {
        id: SpecId::from_uuid(Uuid::from_uuid(row.id)),
        content: OpenApiSpecContent {
            service: ServiceName::new(&row.service)
                .map_err(|error| unusable(UnusableSpecRow::Invariant(error)))?,
            content_hash,
            operations,
        },
        status,
        uploaded_by: ActorRef::parse(&row.uploaded_by)
            .map_err(|error| unusable(UnusableSpecRow::Invariant(error)))?,
        created_at: SystemTime::from(row.created_at),
        activated_at: row.activated_at.map(SystemTime::from),
        retired_at: row.retired_at.map(SystemTime::from),
    }))
}

/// A stored value that cannot be rebuilt is unusable data.
fn unusable(error: UnusableSpecRow) -> RepositoryError {
    RepositoryError::Unavailable(Box::new(error))
}

#[async_trait::async_trait]
impl OpenApiSpecRepository for PgOpenApiSpecRepository {
    async fn find_by_id(&self, id: SpecId) -> Result<Option<OpenApiSpec>, RepositoryError> {
        self.select_by_id(id).await
    }

    async fn find_document(&self, id: SpecId) -> Result<Option<String>, RepositoryError> {
        self.select_document(id).await
    }

    async fn find_by_content_hash(
        &self,
        service: &ServiceName,
        content_hash: &ContentHash,
    ) -> Result<Option<OpenApiSpec>, RepositoryError> {
        self.select_by_content_hash(service, content_hash).await
    }

    async fn find_active(
        &self,
        service: &ServiceName,
    ) -> Result<Vec<OpenApiSpec>, RepositoryError> {
        self.select_active(service).await
    }

    async fn find_page(
        &self,
        query: &OpenApiSpecPageQuery,
    ) -> Result<Vec<OpenApiSpec>, RepositoryError> {
        self.select_page(query).await
    }
}

#[cfg(test)]
mod tests;
