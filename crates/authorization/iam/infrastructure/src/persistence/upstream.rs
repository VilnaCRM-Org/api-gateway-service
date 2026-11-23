//! PostgreSQL implementation of the upstream repository port: reads `iam_upstreams` and runs the
//! upstream statements that the unit of work contributes to a change.
//!
//! The statements are checked at run time, so the offline query metadata does not hold them.

use std::time::SystemTime;

use iam_domain::{
    EntityVersion, RepositoryError, Upstream, UpstreamFields, UpstreamId, UpstreamName,
    UpstreamPageQuery, UpstreamParts, UpstreamProtocol, UpstreamRepository, UpstreamSettingsDraft,
    UpstreamStatement,
};
use shared_domain::Uuid;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;
use sqlx::{PgConnection, PgExecutor};

use crate::persistence::role::{translate, updated};
use crate::persistence::stored::{unusable_field, unusable_value};

/// A statement that selects the columns of an upstream row, followed by `$filter`.
macro_rules! select {
    ($filter:literal) => {
        concat!(
            "SELECT id, name, namespace, service_name, catalog_service, port, protocol,
                forward_credentials, system, connect_timeout_ms, response_timeout_ms,
                concurrency_limit, retry_budget_percent, outlier_threshold, version, created_at,
                updated_at
            FROM iam_upstreams ",
            $filter
        )
    };
}

/// The stored upstream row; it never leaves this module.
#[derive(sqlx::FromRow)]
struct UpstreamRow {
    id: SqlUuid,
    name: String,
    namespace: String,
    service_name: String,
    catalog_service: String,
    port: i32,
    protocol: String,
    forward_credentials: bool,
    system: bool,
    connect_timeout_ms: i64,
    response_timeout_ms: i64,
    concurrency_limit: i64,
    retry_budget_percent: i32,
    outlier_threshold: i64,
    version: i64,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

/// Reads the upstreams that are not deleted.
#[derive(Debug)]
pub struct PgUpstreamRepository {
    pool: sqlx::PgPool,
}

impl PgUpstreamRepository {
    /// Builds the repository over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    async fn find_one_by_id(&self, id: UpstreamId) -> Result<Option<Upstream>, RepositoryError> {
        Ok(select_by_id(&self.pool, id).await?.map(Upstream::restore))
    }

    async fn find_one_by_name(
        &self,
        name: &UpstreamName,
    ) -> Result<Option<Upstream>, RepositoryError> {
        Ok(select_by_name(&self.pool, name)
            .await?
            .map(Upstream::restore))
    }
}

/// The upstream with the identifier, unless it is unknown or deleted.
pub(crate) async fn select_by_id<'executor, E: PgExecutor<'executor>>(
    executor: E,
    id: UpstreamId,
) -> Result<Option<UpstreamParts>, RepositoryError> {
    sqlx::query_as::<_, UpstreamRow>(select!("WHERE id = $1 AND deleted_at IS NULL"))
        .bind(id.as_uuid().as_uuid())
        .fetch_optional(executor)
        .await
        .map_err(translate)?
        .map(restore)
        .transpose()
}

/// The upstream with the name, unless it is unknown or deleted.
pub(crate) async fn select_by_name<'executor, E: PgExecutor<'executor>>(
    executor: E,
    name: &UpstreamName,
) -> Result<Option<UpstreamParts>, RepositoryError> {
    sqlx::query_as::<_, UpstreamRow>(select!("WHERE name = $1 AND deleted_at IS NULL"))
        .bind(name.as_str())
        .fetch_optional(executor)
        .await
        .map_err(translate)?
        .map(restore)
        .transpose()
}

/// One page of upstreams that are not deleted, in the order of their identifiers.
async fn select_page<'executor, E: PgExecutor<'executor>>(
    executor: E,
    query: &UpstreamPageQuery,
) -> Result<Vec<Upstream>, RepositoryError> {
    sqlx::query_as::<_, UpstreamRow>(select!(
        "WHERE deleted_at IS NULL AND ($1::uuid IS NULL OR id > $1) ORDER BY id LIMIT $2"
    ))
    .bind(query.after.map(|id| id.as_uuid().as_uuid()))
    .bind(i64::from(query.limit))
    .fetch_all(executor)
    .await
    .map_err(translate)?
    .into_iter()
    .map(|row| restore(row).map(Upstream::restore))
    .collect()
}

/// Runs one upstream statement inside the caller's transaction. A failure leaves the rollback to
/// the caller.
///
/// # Errors
///
/// [`RepositoryError::AlreadyExists`] when an insert meets a stored id or a name that an upstream
/// that is not deleted holds, [`RepositoryError::Conflict`] when an update finds no upstream that
/// is not deleted at the expected version, and [`RepositoryError::Unavailable`] when the storage
/// fails.
pub async fn save_within(
    connection: &mut PgConnection,
    statement: &UpstreamStatement,
) -> Result<(), RepositoryError> {
    let upstream = statement.upstream();
    match statement.expected() {
        None => insert(connection, upstream).await,
        Some(expected) => update(connection, upstream, expected).await,
    }
}

async fn insert(
    connection: &mut PgConnection,
    upstream: &UpstreamParts,
) -> Result<(), RepositoryError> {
    let settings = &upstream.settings;
    sqlx::query(
        "INSERT INTO iam_upstreams (id, name, namespace, service_name, catalog_service, port,
            protocol, forward_credentials, system, connect_timeout_ms, response_timeout_ms,
            concurrency_limit, retry_budget_percent, outlier_threshold, version, created_at,
            updated_at, deleted_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)",
    )
    .bind(upstream.id.as_uuid().as_uuid())
    .bind(upstream.name.as_str())
    .bind(settings.namespace())
    .bind(settings.service_name())
    .bind(settings.catalog_service().as_str())
    .bind(i32::from(settings.port()))
    .bind(settings.protocol().as_str())
    .bind(settings.forward_credentials())
    .bind(upstream.system)
    .bind(i64::from(settings.connect_timeout_ms()))
    .bind(i64::from(settings.response_timeout_ms()))
    .bind(i64::from(settings.concurrency_limit()))
    .bind(i32::from(settings.retry_budget_percent()))
    .bind(i64::from(settings.outlier_threshold()))
    .bind(upstream.version.value())
    .bind(OffsetDateTime::from(upstream.created_at))
    .bind(OffsetDateTime::from(upstream.updated_at))
    .bind(upstream.deleted_at.map(OffsetDateTime::from))
    .execute(&mut *connection)
    .await
    .map(|_done| ())
    .map_err(translate)
}

/// Updates the settings, the version and the times of the upstream that is not deleted and holds
/// the expected version; the name and the `system` flag never change.
async fn update(
    connection: &mut PgConnection,
    upstream: &UpstreamParts,
    expected: EntityVersion,
) -> Result<(), RepositoryError> {
    let settings = &upstream.settings;
    let written = sqlx::query(
        "UPDATE iam_upstreams SET namespace = $2, service_name = $3, catalog_service = $4,
            port = $5, protocol = $6, forward_credentials = $7, connect_timeout_ms = $8,
            response_timeout_ms = $9, concurrency_limit = $10, retry_budget_percent = $11,
            outlier_threshold = $12, version = $13, updated_at = $14, deleted_at = $15
        WHERE id = $1 AND version = $16 AND deleted_at IS NULL",
    )
    .bind(upstream.id.as_uuid().as_uuid())
    .bind(settings.namespace())
    .bind(settings.service_name())
    .bind(settings.catalog_service().as_str())
    .bind(i32::from(settings.port()))
    .bind(settings.protocol().as_str())
    .bind(settings.forward_credentials())
    .bind(i64::from(settings.connect_timeout_ms()))
    .bind(i64::from(settings.response_timeout_ms()))
    .bind(i64::from(settings.concurrency_limit()))
    .bind(i32::from(settings.retry_budget_percent()))
    .bind(i64::from(settings.outlier_threshold()))
    .bind(upstream.version.value())
    .bind(OffsetDateTime::from(upstream.updated_at))
    .bind(upstream.deleted_at.map(OffsetDateTime::from))
    .bind(expected.value())
    .execute(&mut *connection)
    .await
    .map_err(translate)?;
    updated(written.rows_affected())
}

/// Rebuilds one stored upstream through the value objects.
fn restore(row: UpstreamRow) -> Result<UpstreamParts, RepositoryError> {
    let draft = UpstreamSettingsDraft {
        namespace: row.namespace,
        service_name: row.service_name,
        catalog_service: row.catalog_service,
        port: i64::from(row.port),
        protocol: UpstreamProtocol::parse(&row.protocol)
            .ok_or_else(|| unusable_field("protocol"))?,
        forward_credentials: row.forward_credentials,
        connect_timeout_ms: row.connect_timeout_ms,
        response_timeout_ms: row.response_timeout_ms,
        concurrency_limit: row.concurrency_limit,
        retry_budget_percent: i64::from(row.retry_budget_percent),
        outlier_threshold: row.outlier_threshold,
    };
    let (name, settings) = UpstreamFields::new(&row.name, &draft)
        .map_err(|_violations| unusable_field("settings"))?
        .into_parts();
    Ok(UpstreamParts {
        id: UpstreamId::from_uuid(Uuid::from_uuid(row.id)),
        name,
        settings,
        system: row.system,
        version: EntityVersion::new(row.version).map_err(unusable_value)?,
        created_at: SystemTime::from(row.created_at),
        updated_at: SystemTime::from(row.updated_at),
        deleted_at: None,
    })
}

#[async_trait::async_trait]
impl UpstreamRepository for PgUpstreamRepository {
    async fn find_by_id(&self, id: UpstreamId) -> Result<Option<Upstream>, RepositoryError> {
        self.find_one_by_id(id).await
    }

    async fn find_by_name(&self, name: &UpstreamName) -> Result<Option<Upstream>, RepositoryError> {
        self.find_one_by_name(name).await
    }

    async fn find_page(&self, query: &UpstreamPageQuery) -> Result<Vec<Upstream>, RepositoryError> {
        select_page(&self.pool, query).await
    }
}

#[cfg(test)]
mod tests;
