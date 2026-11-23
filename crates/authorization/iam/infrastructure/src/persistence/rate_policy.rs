//! PostgreSQL implementation of the rate policy repository port: reads `iam_rate_policies` and runs
//! the rate policy statements that the unit of work contributes to a change.
//!
//! The statements are checked at run time, so the offline query metadata does not hold them.

use std::collections::BTreeMap;
use std::time::SystemTime;

use iam_domain::{
    EntityVersion, RateFallback, RateKeyKind, RatePolicy, RatePolicyDraft, RatePolicyFields,
    RatePolicyId, RatePolicyPageQuery, RatePolicyParts, RatePolicyRepository, RatePolicyStatement,
    RepositoryError,
};
use shared_domain::Uuid;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;
use sqlx::{PgConnection, PgExecutor};

use crate::persistence::role::{translate, updated};
use crate::persistence::stored::{unusable_field, unusable_value};

/// A statement that selects the columns of a rate policy row, followed by `$filter`.
macro_rules! select {
    ($filter:literal) => {
        concat!(
            "SELECT id, name, key_kind, request_limit, period_seconds, burst, fallback, version,
                created_at, updated_at
            FROM iam_rate_policies ",
            $filter
        )
    };
}

/// The stored rate policy row; it never leaves this module.
#[derive(sqlx::FromRow)]
struct RatePolicyRow {
    id: SqlUuid,
    name: String,
    key_kind: String,
    request_limit: i64,
    period_seconds: i64,
    burst: i64,
    fallback: String,
    version: i64,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

/// Reads the rate policies that are not deleted.
#[derive(Debug)]
pub struct PgRatePolicyRepository {
    pool: sqlx::PgPool,
}

impl PgRatePolicyRepository {
    /// Builds the repository over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    async fn find_one(&self, id: RatePolicyId) -> Result<Option<RatePolicy>, RepositoryError> {
        Ok(select_by_id(&self.pool, id).await?.map(RatePolicy::restore))
    }

    /// The rate policies of `ids` that exist and are not deleted, in the order of `ids`.
    async fn select_many(&self, ids: &[RatePolicyId]) -> Result<Vec<RatePolicy>, RepositoryError> {
        let wanted: Vec<SqlUuid> = ids.iter().map(|id| id.as_uuid().as_uuid()).collect();
        let rows = sqlx::query_as::<_, RatePolicyRow>(select!(
            "WHERE id = ANY($1::uuid[]) AND deleted_at IS NULL"
        ))
        .bind(wanted)
        .fetch_all(&self.pool)
        .await
        .map_err(translate)?;
        let found = rows
            .into_iter()
            .map(|row| restore(row).map(|parts| (parts.id, parts)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        Ok(ids
            .iter()
            .filter_map(|id| found.get(id))
            .map(|parts| RatePolicy::restore(parts.clone()))
            .collect())
    }

    async fn select_page(
        &self,
        query: &RatePolicyPageQuery,
    ) -> Result<Vec<RatePolicy>, RepositoryError> {
        sqlx::query_as::<_, RatePolicyRow>(select!(
            "WHERE deleted_at IS NULL AND ($1::uuid IS NULL OR id > $1) ORDER BY id LIMIT $2"
        ))
        .bind(query.after.map(|id| id.as_uuid().as_uuid()))
        .bind(i64::from(query.limit))
        .fetch_all(&self.pool)
        .await
        .map_err(translate)?
        .into_iter()
        .map(|row| restore(row).map(RatePolicy::restore))
        .collect()
    }
}

/// The rate policy with the identifier, unless it is unknown or deleted.
pub(crate) async fn select_by_id<'executor, E: PgExecutor<'executor>>(
    executor: E,
    id: RatePolicyId,
) -> Result<Option<RatePolicyParts>, RepositoryError> {
    sqlx::query_as::<_, RatePolicyRow>(select!("WHERE id = $1 AND deleted_at IS NULL"))
        .bind(id.as_uuid().as_uuid())
        .fetch_optional(executor)
        .await
        .map_err(translate)?
        .map(restore)
        .transpose()
}

/// Runs one rate policy statement inside the caller's transaction. A failure leaves the rollback
/// to the caller.
///
/// # Errors
///
/// [`RepositoryError::AlreadyExists`] when an insert meets a stored id or a name that a rate
/// policy that is not deleted holds, [`RepositoryError::Conflict`] when an update finds no rate
/// policy that is not deleted at the expected version, and [`RepositoryError::Unavailable`] when
/// the storage fails.
pub async fn save_within(
    connection: &mut PgConnection,
    statement: &RatePolicyStatement,
) -> Result<(), RepositoryError> {
    let policy = statement.rate_policy();
    match statement.expected() {
        None => insert(connection, policy).await,
        Some(expected) => update(connection, policy, expected).await,
    }
}

async fn insert(
    connection: &mut PgConnection,
    policy: &RatePolicyParts,
) -> Result<(), RepositoryError> {
    let fields = &policy.fields;
    sqlx::query(
        "INSERT INTO iam_rate_policies (id, name, key_kind, request_limit, period_seconds, burst,
            fallback, version, created_at, updated_at, deleted_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(policy.id.as_uuid().as_uuid())
    .bind(fields.name())
    .bind(fields.key_kind().as_str())
    .bind(i64::from(fields.limit()))
    .bind(i64::from(fields.period_seconds()))
    .bind(i64::from(fields.burst()))
    .bind(fields.fallback().as_str())
    .bind(policy.version.value())
    .bind(OffsetDateTime::from(policy.created_at))
    .bind(OffsetDateTime::from(policy.updated_at))
    .bind(policy.deleted_at.map(OffsetDateTime::from))
    .execute(&mut *connection)
    .await
    .map(|_done| ())
    .map_err(translate)
}

/// Updates the configuration, the version and the times of the rate policy that is not deleted and
/// holds the expected version.
async fn update(
    connection: &mut PgConnection,
    policy: &RatePolicyParts,
    expected: EntityVersion,
) -> Result<(), RepositoryError> {
    let fields = &policy.fields;
    let written = sqlx::query(
        "UPDATE iam_rate_policies SET name = $2, key_kind = $3, request_limit = $4,
            period_seconds = $5, burst = $6, fallback = $7, version = $8, updated_at = $9,
            deleted_at = $10
        WHERE id = $1 AND version = $11 AND deleted_at IS NULL",
    )
    .bind(policy.id.as_uuid().as_uuid())
    .bind(fields.name())
    .bind(fields.key_kind().as_str())
    .bind(i64::from(fields.limit()))
    .bind(i64::from(fields.period_seconds()))
    .bind(i64::from(fields.burst()))
    .bind(fields.fallback().as_str())
    .bind(policy.version.value())
    .bind(OffsetDateTime::from(policy.updated_at))
    .bind(policy.deleted_at.map(OffsetDateTime::from))
    .bind(expected.value())
    .execute(&mut *connection)
    .await
    .map_err(translate)?;
    updated(written.rows_affected())
}

/// Rebuilds one stored rate policy through the value objects.
fn restore(row: RatePolicyRow) -> Result<RatePolicyParts, RepositoryError> {
    let draft = RatePolicyDraft {
        name: row.name,
        key_kind: RateKeyKind::parse(&row.key_kind).ok_or_else(|| unusable_field("key_kind"))?,
        limit: row.request_limit,
        period_seconds: row.period_seconds,
        burst: row.burst,
        fallback: RateFallback::parse(&row.fallback).ok_or_else(|| unusable_field("fallback"))?,
    };
    Ok(RatePolicyParts {
        id: RatePolicyId::from_uuid(Uuid::from_uuid(row.id)),
        fields: RatePolicyFields::new(draft).map_err(|_violations| unusable_field("fields"))?,
        version: EntityVersion::new(row.version).map_err(unusable_value)?,
        created_at: SystemTime::from(row.created_at),
        updated_at: SystemTime::from(row.updated_at),
        deleted_at: None,
    })
}

#[async_trait::async_trait]
impl RatePolicyRepository for PgRatePolicyRepository {
    async fn find_by_id(&self, id: RatePolicyId) -> Result<Option<RatePolicy>, RepositoryError> {
        self.find_one(id).await
    }

    async fn find_many(&self, ids: &[RatePolicyId]) -> Result<Vec<RatePolicy>, RepositoryError> {
        self.select_many(ids).await
    }

    async fn find_page(
        &self,
        query: &RatePolicyPageQuery,
    ) -> Result<Vec<RatePolicy>, RepositoryError> {
        self.select_page(query).await
    }
}

#[cfg(test)]
mod tests;
