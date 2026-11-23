//! PostgreSQL implementation of the specification repository port: reads `iam_graphql_specs` with
//! its fields and possible types, and runs the insert statement that the unit of work contributes
//! to a change.
//!
//! The SDL and the coordinates of a stored version are written once, by the insert; no statement
//! of this module updates them, and a trigger of the table refuses it too.

use std::collections::BTreeMap;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, ContentHash, GqlName, GraphQlCoordinate, GraphQlField, GraphQlSpec,
    GraphQlSpecContent, GraphQlSpecPageQuery, GraphQlSpecParts, GraphQlSpecRepository,
    GraphQlSpecStatement, GraphQlTypeGraph, InvalidIamValue, InvalidSpec, PermissionFlags,
    RepositoryError, ServiceName, SpecId, SpecStatus, SpecTransition,
};
use shared_domain::Uuid;
use sqlx::PgConnection;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;

use crate::persistence::catalogue::expect_rows;
use crate::persistence::role::translate;

/// Reads the stored specification versions.
#[derive(Debug)]
pub struct PgGraphQlSpecRepository {
    pool: sqlx::PgPool,
}

/// A stored value that cannot be turned back into a domain value.
#[derive(Debug, thiserror::Error)]
enum UnusableSpecRow {
    /// A stored name, hash or status is not valid.
    #[error("a stored specification value is invalid: {0}")]
    Value(&'static str),
    /// The stored fields do not make a valid type graph.
    #[error("the stored fields do not make a type graph")]
    Graph(#[source] InvalidSpec),
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

/// The stored field row; it never leaves this crate.
pub(crate) struct FieldRow {
    pub(crate) spec_id: SqlUuid,
    pub(crate) type_name: String,
    pub(crate) field_name: String,
    pub(crate) return_type: String,
    pub(crate) sensitive: bool,
    pub(crate) audit_always: bool,
}

/// The stored possible type row; it never leaves this crate.
pub(crate) struct PossibleTypeRow {
    pub(crate) spec_id: SqlUuid,
    pub(crate) abstract_type: String,
    pub(crate) possible_type: String,
}

impl PgGraphQlSpecRepository {
    /// Builds the repository over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    async fn select_by_id(&self, id: SpecId) -> Result<Option<GraphQlSpec>, RepositoryError> {
        let rows = sqlx::query_as!(
            SpecRow,
            "SELECT id, service, content_hash, status, uploaded_by, created_at, activated_at,
                retired_at
            FROM iam_graphql_specs WHERE id = $1",
            id.as_uuid().as_uuid(),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(translate)?;
        Ok(self.restore_all(rows).await?.pop())
    }

    async fn select_sdl(&self, id: SpecId) -> Result<Option<String>, RepositoryError> {
        sqlx::query_scalar!(
            "SELECT sdl FROM iam_graphql_specs WHERE id = $1",
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
    ) -> Result<Option<GraphQlSpec>, RepositoryError> {
        let rows = sqlx::query_as!(
            SpecRow,
            "SELECT id, service, content_hash, status, uploaded_by, created_at, activated_at,
                retired_at
            FROM iam_graphql_specs WHERE service = $1 AND content_hash = $2",
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
    ) -> Result<Vec<GraphQlSpec>, RepositoryError> {
        let rows = sqlx::query_as!(
            SpecRow,
            "SELECT id, service, content_hash, status, uploaded_by, created_at, activated_at,
                retired_at
            FROM iam_graphql_specs WHERE service = $1 AND status = 'active' ORDER BY id",
            service.as_str(),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(translate)?;
        self.restore_all(rows).await
    }

    async fn select_page(
        &self,
        query: &GraphQlSpecPageQuery,
    ) -> Result<Vec<GraphQlSpec>, RepositoryError> {
        let rows = sqlx::query_as!(
            SpecRow,
            "SELECT id, service, content_hash, status, uploaded_by, created_at, activated_at,
                retired_at
            FROM iam_graphql_specs
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

    /// Rebuilds the versions of `rows` with their fields and possible types, in the order of
    /// `rows`. The content of a version never changes after the insert, so the reads need no
    /// common snapshot.
    async fn restore_all(&self, rows: Vec<SpecRow>) -> Result<Vec<GraphQlSpec>, RepositoryError> {
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<SqlUuid> = rows.iter().map(|row| row.id).collect();
        let mut fields = group(self.select_fields(&ids).await?, |row| row.spec_id);
        let mut possible = group(self.select_possible_types(&ids).await?, |row| row.spec_id);
        rows.iter()
            .map(|row| {
                let graph = graph(
                    &fields.remove(&row.id).unwrap_or_default(),
                    &possible.remove(&row.id).unwrap_or_default(),
                )?;
                restore(row, graph)
            })
            .collect()
    }

    async fn select_fields(&self, ids: &[SqlUuid]) -> Result<Vec<FieldRow>, RepositoryError> {
        sqlx::query_as!(
            FieldRow,
            "SELECT spec_id, type_name, field_name, return_type, sensitive, audit_always
            FROM iam_graphql_spec_fields WHERE spec_id = ANY($1)",
            ids,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(translate)
    }

    async fn select_possible_types(
        &self,
        ids: &[SqlUuid],
    ) -> Result<Vec<PossibleTypeRow>, RepositoryError> {
        sqlx::query_as!(
            PossibleTypeRow,
            "SELECT spec_id, abstract_type, possible_type
            FROM iam_graphql_spec_possible_types WHERE spec_id = ANY($1)",
            ids,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(translate)
    }
}

/// Groups `rows` by the key of each row.
pub(crate) fn group<R>(rows: Vec<R>, key: impl Fn(&R) -> SqlUuid) -> BTreeMap<SqlUuid, Vec<R>> {
    let mut grouped: BTreeMap<SqlUuid, Vec<R>> = BTreeMap::new();
    for row in rows {
        grouped.entry(key(&row)).or_default().push(row);
    }
    grouped
}

/// Runs one specification statement inside the caller's transaction: the version row, then its
/// fields and possible types. A failure leaves the rollback to the caller.
///
/// # Errors
///
/// [`RepositoryError::AlreadyExists`] when the id is stored or the service already has a version
/// with the same content hash, and [`RepositoryError::Unavailable`] when the storage fails or the
/// hash of the version is not the SHA-256 hash of its SDL.
pub async fn save_within(
    connection: &mut PgConnection,
    statement: &GraphQlSpecStatement,
) -> Result<(), RepositoryError> {
    let row = WriteRow::of(statement);
    insert_spec(connection, &row).await?;
    insert_fields(connection, &row).await?;
    insert_possible_types(connection, &row).await
}

/// Moves the version of `transition` to its new status inside the caller's transaction.
///
/// The move happens only when the version still holds the status the change was decided against.
/// Only the status and its times change: the content of a stored version never does.
///
/// # Errors
///
/// [`RepositoryError::Conflict`] when the version is missing or is no longer in the expected
/// status, and [`RepositoryError::Unavailable`] when the storage fails.
pub async fn transition_within(
    connection: &mut PgConnection,
    transition: &SpecTransition,
) -> Result<(), RepositoryError> {
    let written = sqlx::query!(
        "UPDATE iam_graphql_specs SET status = $2, activated_at = $3, retired_at = $4
        WHERE id = $1 AND status = $5",
        transition.spec_id.as_uuid().as_uuid(),
        transition.to.as_str(),
        transition.activated_at.map(OffsetDateTime::from),
        transition.retired_at.map(OffsetDateTime::from),
        transition.from.as_str(),
    )
    .execute(&mut *connection)
    .await
    .map_err(translate)?;
    expect_rows(written.rows_affected(), 1)
}

/// The column values of one version write; they never leave this module.
#[derive(Debug, PartialEq, Eq)]
struct WriteRow {
    id: SqlUuid,
    service: String,
    content_hash: Vec<u8>,
    sdl: String,
    status: &'static str,
    uploaded_by: String,
    created_at: OffsetDateTime,
    activated_at: Option<OffsetDateTime>,
    retired_at: Option<OffsetDateTime>,
    fields: FieldColumns,
    possible_types: PossibleTypeColumns,
}

/// The field rows of a version as parallel columns, one element per field.
#[derive(Debug, Default, PartialEq, Eq)]
struct FieldColumns {
    type_names: Vec<String>,
    field_names: Vec<String>,
    return_types: Vec<String>,
    sensitive: Vec<bool>,
    audit_always: Vec<bool>,
}

/// The possible type rows of a version as parallel columns, one element per pair.
#[derive(Debug, Default, PartialEq, Eq)]
struct PossibleTypeColumns {
    abstract_types: Vec<String>,
    possible_types: Vec<String>,
}

impl WriteRow {
    /// The column values of `statement`.
    fn of(statement: &GraphQlSpecStatement) -> Self {
        let spec = statement.spec();
        let graph = &spec.content.type_graph;
        let mut fields = FieldColumns::default();
        for (coordinate, field) in graph.fields() {
            fields.type_names.push(coordinate.type_name().to_string());
            fields.field_names.push(coordinate.field().to_string());
            fields.return_types.push(field.return_type.to_string());
            fields.sensitive.push(field.flags.is_sensitive());
            fields.audit_always.push(field.flags.is_audit_always());
        }
        let mut possible_types = PossibleTypeColumns::default();
        for (abstract_type, possible_type) in graph.possible_type_pairs() {
            possible_types
                .abstract_types
                .push(abstract_type.to_string());
            possible_types
                .possible_types
                .push(possible_type.to_string());
        }
        Self {
            id: spec.id.as_uuid().as_uuid(),
            service: spec.content.service.to_string(),
            content_hash: spec.content.content_hash.as_bytes().to_vec(),
            sdl: statement.sdl().to_owned(),
            status: spec.status.as_str(),
            uploaded_by: spec.uploaded_by.to_string(),
            created_at: OffsetDateTime::from(spec.created_at),
            activated_at: spec.activated_at.map(OffsetDateTime::from),
            retired_at: spec.retired_at.map(OffsetDateTime::from),
            fields,
            possible_types,
        }
    }
}

/// Inserts the version row. The hash is computed by SQL `sha256()` over the SDL and the row is
/// written only when it equals the hash of the version; a unique violation is a duplicate.
///
/// The text values travel as one `text[]` parameter in the order service, SDL, status and
/// uploader, which keeps the parameter list short.
async fn insert_spec(connection: &mut PgConnection, row: &WriteRow) -> Result<(), RepositoryError> {
    let texts = [
        row.service.clone(),
        row.sdl.clone(),
        row.status.to_owned(),
        row.uploaded_by.clone(),
    ];
    let written = sqlx::query!(
        "INSERT INTO iam_graphql_specs (id, service, content_hash, sdl, status, uploaded_by,
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

/// No affected row means that the hash of the version is not the hash of its SDL.
fn hashed(rows_affected: u64) -> Result<(), RepositoryError> {
    if rows_affected == 0 {
        Err(RepositoryError::Unavailable(
            "the content hash is not the SHA-256 hash of the SDL".into(),
        ))
    } else {
        Ok(())
    }
}

/// Inserts the field rows of the version, one row per element of the columns.
async fn insert_fields(
    connection: &mut PgConnection,
    row: &WriteRow,
) -> Result<(), RepositoryError> {
    sqlx::query!(
        "INSERT INTO iam_graphql_spec_fields (spec_id, type_name, field_name, return_type,
            sensitive, audit_always)
        SELECT $1::uuid, type_name, field_name, return_type, sensitive, audit_always
        FROM UNNEST($2::text[], $3::text[], $4::text[], $5::bool[], $6::bool[])
            AS fields (type_name, field_name, return_type, sensitive, audit_always)",
        row.id,
        row.fields.type_names.as_slice(),
        row.fields.field_names.as_slice(),
        row.fields.return_types.as_slice(),
        row.fields.sensitive.as_slice(),
        row.fields.audit_always.as_slice(),
    )
    .execute(&mut *connection)
    .await
    .map(|_done| ())
    .map_err(translate)
}

/// Inserts the possible type rows of the version, one row per element of the columns.
async fn insert_possible_types(
    connection: &mut PgConnection,
    row: &WriteRow,
) -> Result<(), RepositoryError> {
    sqlx::query!(
        "INSERT INTO iam_graphql_spec_possible_types (spec_id, abstract_type, possible_type)
        SELECT $1::uuid, abstract_type, possible_type FROM UNNEST($2::text[], $3::text[])
            AS pairs (abstract_type, possible_type)",
        row.id,
        row.possible_types.abstract_types.as_slice(),
        row.possible_types.possible_types.as_slice(),
    )
    .execute(&mut *connection)
    .await
    .map(|_done| ())
    .map_err(translate)
}

/// Rebuilds the type graph of the stored fields and possible types through the value objects.
pub(crate) fn graph(
    fields: &[FieldRow],
    possible: &[PossibleTypeRow],
) -> Result<GraphQlTypeGraph, RepositoryError> {
    let fields = fields
        .iter()
        .map(field)
        .collect::<Result<Vec<_>, RepositoryError>>()?;
    let possible = possible
        .iter()
        .map(|row| Ok((name(&row.abstract_type)?, name(&row.possible_type)?)))
        .collect::<Result<Vec<_>, RepositoryError>>()?;
    GraphQlTypeGraph::new(fields, possible).map_err(|error| unusable(UnusableSpecRow::Graph(error)))
}

/// Rebuilds one stored field.
fn field(row: &FieldRow) -> Result<(GraphQlCoordinate, GraphQlField), RepositoryError> {
    let mut flags = PermissionFlags::NONE;
    if row.sensitive {
        flags = flags.with_sensitive();
    }
    if row.audit_always {
        flags = flags.with_audit_always();
    }
    Ok((
        GraphQlCoordinate::new(name(&row.type_name)?, name(&row.field_name)?),
        GraphQlField {
            return_type: name(&row.return_type)?,
            flags,
        },
    ))
}

/// A stored GraphQL name.
fn name(value: &str) -> Result<GqlName, RepositoryError> {
    GqlName::parse(value).ok_or_else(|| unusable(UnusableSpecRow::Value("a GraphQL name")))
}

/// Rebuilds one stored version around its type graph; a value that breaks an invariant is unusable
/// data.
fn restore(row: &SpecRow, type_graph: GraphQlTypeGraph) -> Result<GraphQlSpec, RepositoryError> {
    let content_hash = ContentHash::new(&row.content_hash)
        .ok_or_else(|| unusable(UnusableSpecRow::Value("a content hash")))?;
    let status = SpecStatus::parse(&row.status)
        .ok_or_else(|| unusable(UnusableSpecRow::Value("a status")))?;
    Ok(GraphQlSpec::restore(GraphQlSpecParts {
        id: SpecId::from_uuid(Uuid::from_uuid(row.id)),
        content: GraphQlSpecContent {
            service: ServiceName::new(&row.service)
                .map_err(|error| unusable(UnusableSpecRow::Invariant(error)))?,
            content_hash,
            type_graph,
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
impl GraphQlSpecRepository for PgGraphQlSpecRepository {
    async fn find_by_id(&self, id: SpecId) -> Result<Option<GraphQlSpec>, RepositoryError> {
        self.select_by_id(id).await
    }

    async fn find_sdl(&self, id: SpecId) -> Result<Option<String>, RepositoryError> {
        self.select_sdl(id).await
    }

    async fn find_by_content_hash(
        &self,
        service: &ServiceName,
        content_hash: &ContentHash,
    ) -> Result<Option<GraphQlSpec>, RepositoryError> {
        self.select_by_content_hash(service, content_hash).await
    }

    async fn find_active(
        &self,
        service: &ServiceName,
    ) -> Result<Vec<GraphQlSpec>, RepositoryError> {
        self.select_active(service).await
    }

    async fn find_page(
        &self,
        query: &GraphQlSpecPageQuery,
    ) -> Result<Vec<GraphQlSpec>, RepositoryError> {
        self.select_page(query).await
    }
}

#[cfg(test)]
mod tests;
