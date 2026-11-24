//! PostgreSQL implementation of the route repository port: reads `iam_routes` and
//! `iam_route_rate_policies`, and runs the route statements that the unit of work contributes to a
//! change.
//!
//! The statements are checked at run time, so the offline query metadata does not hold them.

use std::time::SystemTime;

use iam_domain::{
    EnforcementMode, EntityVersion, HttpMethod, RatePolicyId, RepositoryError, RetryPolicy, Route,
    RouteDraft, RouteFields, RouteFlag, RouteFlags, RouteHost, RouteId, RoutePageQuery, RouteParts,
    RouteRepository, RouteStatement, ServiceName, UpstreamId,
};
use shared_domain::Uuid;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;
use sqlx::{PgConnection, PgExecutor};

use crate::persistence::role::{translate, updated};
use crate::persistence::stored::{count_of, translate_reference, unusable_field, unusable_value};
use crate::policy_state::json_state_record_codec::{cors_from_json, cors_to_json};

/// A statement that selects the columns of a route row, with its rate policies in their stored
/// order, followed by `$filter`.
macro_rules! select {
    ($filter:literal) => {
        concat!(
            "SELECT id, host, methods, path_pattern, service, upstream_id,
                ARRAY[graphql, streaming, anonymous] AS flags, enforcement, body_limit,
                request_timeout_ms, idle_timeout_ms, retry, cors::text AS cors, system, version,
                created_at, updated_at,
                ARRAY(SELECT rate_policy_id FROM iam_route_rate_policies
                    WHERE route_id = iam_routes.id ORDER BY position) AS rate_policies
            FROM iam_routes ",
            $filter
        )
    };
}

/// The stored route row, with the identifiers of its rate policies in their stored order; it never
/// leaves this module.
#[derive(sqlx::FromRow)]
struct RouteRow {
    id: SqlUuid,
    host: String,
    methods: Vec<String>,
    path_pattern: String,
    service: String,
    upstream_id: SqlUuid,
    /// Whether the route is `graphql`, `streaming` and `anonymous`, in this order.
    flags: Vec<bool>,
    enforcement: String,
    body_limit: i64,
    request_timeout_ms: i64,
    idle_timeout_ms: i64,
    retry: String,
    cors: Option<String>,
    system: bool,
    version: i64,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    rate_policies: Vec<SqlUuid>,
}

/// Reads the routes that are not deleted, with their rate policies.
#[derive(Debug)]
pub struct PgRouteRepository {
    pool: sqlx::PgPool,
}

impl PgRouteRepository {
    /// Builds the repository over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    async fn find_one(&self, id: RouteId) -> Result<Option<Route>, RepositoryError> {
        Ok(select_by_id(&self.pool, id).await?.map(Route::restore))
    }

    async fn select_page(&self, query: &RoutePageQuery) -> Result<Vec<Route>, RepositoryError> {
        let rows = sqlx::query_as::<_, RouteRow>(select!(
            "WHERE deleted_at IS NULL
                AND ($1::uuid IS NULL OR id > $1)
                AND ($2::text IS NULL OR host = $2)
                AND ($3::uuid IS NULL OR upstream_id = $3)
                AND ($4::text IS NULL OR service = $4)
            ORDER BY id
            LIMIT $5"
        ))
        .bind(query.after.map(|id| id.as_uuid().as_uuid()))
        .bind(query.host.as_ref().map(RouteHost::as_str))
        .bind(query.upstream.map(|id| id.as_uuid().as_uuid()))
        .bind(query.service.as_ref().map(ServiceName::as_str))
        .bind(i64::from(query.limit))
        .fetch_all(&self.pool)
        .await
        .map_err(translate)?;
        restore_all(rows)
    }

    async fn select_by_host(&self, host: &RouteHost) -> Result<Vec<Route>, RepositoryError> {
        Ok(select_parts_by_host(&self.pool, host)
            .await?
            .into_iter()
            .map(Route::restore)
            .collect())
    }

    async fn count_upstream(&self, upstream: UpstreamId) -> Result<u64, RepositoryError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM iam_routes WHERE upstream_id = $1 AND deleted_at IS NULL",
        )
        .bind(upstream.as_uuid().as_uuid())
        .fetch_one(&self.pool)
        .await
        .map_err(translate)?;
        count_of(count)
    }

    async fn count_rate_policy(&self, policy: RatePolicyId) -> Result<u64, RepositoryError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM iam_route_rate_policies AS applied
            JOIN iam_routes AS routes ON routes.id = applied.route_id
            WHERE applied.rate_policy_id = $1 AND routes.deleted_at IS NULL",
        )
        .bind(policy.as_uuid().as_uuid())
        .fetch_one(&self.pool)
        .await
        .map_err(translate)?;
        count_of(count)
    }
}

/// The route with the identifier, unless it is unknown or deleted.
pub(crate) async fn select_by_id<'executor, E: PgExecutor<'executor>>(
    executor: E,
    id: RouteId,
) -> Result<Option<RouteParts>, RepositoryError> {
    sqlx::query_as::<_, RouteRow>(select!("WHERE id = $1 AND deleted_at IS NULL"))
        .bind(id.as_uuid().as_uuid())
        .fetch_optional(executor)
        .await
        .map_err(translate)?
        .map(restore)
        .transpose()
}

/// The routes of the host that are not deleted, by identifier, read through `executor`: the
/// connection of a transaction reads the routes that the transaction sees, which the checks under
/// the lock of the policy epoch need.
pub(crate) async fn select_parts_by_host<'executor, E: PgExecutor<'executor>>(
    executor: E,
    host: &RouteHost,
) -> Result<Vec<RouteParts>, RepositoryError> {
    sqlx::query_as::<_, RouteRow>(select!(
        "WHERE host = $1 AND deleted_at IS NULL ORDER BY id"
    ))
    .bind(host.as_str())
    .fetch_all(executor)
    .await
    .map_err(translate)?
    .into_iter()
    .map(restore)
    .collect()
}

/// Runs one route statement inside the caller's transaction: the route row first, then its rate
/// policies. A failure leaves the rollback to the caller.
///
/// # Errors
///
/// [`RepositoryError::AlreadyExists`] when an insert meets a stored id,
/// [`RepositoryError::Conflict`] when an update finds no route that is not deleted at the expected
/// version or the route names an upstream or a rate policy that is not stored, and
/// [`RepositoryError::Unavailable`] when the storage fails.
pub async fn save_within(
    connection: &mut PgConnection,
    statement: &RouteStatement,
) -> Result<(), RepositoryError> {
    let route = statement.route();
    match statement.expected() {
        None => insert(connection, route).await?,
        Some(expected) => update(connection, route, expected).await?,
    }
    replace_rate_policies(connection, route).await
}

/// The methods of a route as the texts the `methods` column holds.
fn method_texts(route: &RouteParts) -> Vec<&'static str> {
    route
        .fields
        .methods()
        .iter()
        .copied()
        .map(HttpMethod::as_str)
        .collect()
}

/// The canonical JSON of the CORS policy of a route, when it has one.
fn cors_text(route: &RouteParts) -> Option<String> {
    route.fields.cors().map(cors_to_json)
}

async fn insert(connection: &mut PgConnection, route: &RouteParts) -> Result<(), RepositoryError> {
    let fields = &route.fields;
    let flags = fields.flags();
    sqlx::query(
        "INSERT INTO iam_routes (id, host, methods, path_pattern, service, upstream_id, graphql,
            streaming, anonymous, enforcement, body_limit, request_timeout_ms, idle_timeout_ms,
            retry, cors, system, version, created_at, updated_at, deleted_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15::text::jsonb,
            $16, $17, $18, $19, $20)",
    )
    .bind(route.id.as_uuid().as_uuid())
    .bind(fields.host().as_str())
    .bind(method_texts(route))
    .bind(fields.path_pattern().as_str())
    .bind(fields.service().as_str())
    .bind(fields.upstream_id().as_uuid().as_uuid())
    .bind(flags.graphql())
    .bind(flags.streaming())
    .bind(flags.anonymous())
    .bind(fields.enforcement().as_str())
    .bind(i64::try_from(fields.body_limit().bytes()).unwrap_or(i64::MAX))
    .bind(i64::from(fields.timeouts().request_ms()))
    .bind(i64::from(fields.timeouts().idle_ms()))
    .bind(fields.retry().as_str())
    .bind(cors_text(route))
    .bind(route.system)
    .bind(route.version.value())
    .bind(OffsetDateTime::from(route.created_at))
    .bind(OffsetDateTime::from(route.updated_at))
    .bind(route.deleted_at.map(OffsetDateTime::from))
    .execute(&mut *connection)
    .await
    .map(|_done| ())
    .map_err(translate_reference)
}

/// Updates the configuration, the version, the times and the `system` flag of the route that is
/// not deleted and holds the expected version. Only the repair of the IAM seed changes the flag:
/// every other change keeps the stored value in the route it hands over.
async fn update(
    connection: &mut PgConnection,
    route: &RouteParts,
    expected: EntityVersion,
) -> Result<(), RepositoryError> {
    let fields = &route.fields;
    let flags = fields.flags();
    let written = sqlx::query(
        "UPDATE iam_routes SET host = $2, methods = $3, path_pattern = $4, service = $5,
            upstream_id = $6, graphql = $7, streaming = $8, anonymous = $9, enforcement = $10,
            body_limit = $11, request_timeout_ms = $12, idle_timeout_ms = $13, retry = $14,
            cors = $15::text::jsonb, version = $16, updated_at = $17, deleted_at = $18,
            system = $20
        WHERE id = $1 AND version = $19 AND deleted_at IS NULL",
    )
    .bind(route.id.as_uuid().as_uuid())
    .bind(fields.host().as_str())
    .bind(method_texts(route))
    .bind(fields.path_pattern().as_str())
    .bind(fields.service().as_str())
    .bind(fields.upstream_id().as_uuid().as_uuid())
    .bind(flags.graphql())
    .bind(flags.streaming())
    .bind(flags.anonymous())
    .bind(fields.enforcement().as_str())
    .bind(i64::try_from(fields.body_limit().bytes()).unwrap_or(i64::MAX))
    .bind(i64::from(fields.timeouts().request_ms()))
    .bind(i64::from(fields.timeouts().idle_ms()))
    .bind(fields.retry().as_str())
    .bind(cors_text(route))
    .bind(route.version.value())
    .bind(OffsetDateTime::from(route.updated_at))
    .bind(route.deleted_at.map(OffsetDateTime::from))
    .bind(expected.value())
    .bind(route.system)
    .execute(&mut *connection)
    .await
    .map_err(translate_reference)?;
    updated(written.rows_affected())
}

/// Replaces the rate policies of the route with those of its configuration, numbered from 1 in the
/// order they apply.
async fn replace_rate_policies(
    connection: &mut PgConnection,
    route: &RouteParts,
) -> Result<(), RepositoryError> {
    let id = route.id.as_uuid().as_uuid();
    sqlx::query("DELETE FROM iam_route_rate_policies WHERE route_id = $1")
        .bind(id)
        .execute(&mut *connection)
        .await
        .map_err(translate)?;
    let policies: Vec<SqlUuid> = route
        .fields
        .rate_policies()
        .iter()
        .map(|policy| policy.as_uuid().as_uuid())
        .collect();
    sqlx::query(
        "INSERT INTO iam_route_rate_policies (route_id, rate_policy_id, position)
        SELECT $1, item.policy_id, item.ordinal::integer
        FROM UNNEST($2::uuid[]) WITH ORDINALITY AS item (policy_id, ordinal)",
    )
    .bind(id)
    .bind(policies)
    .execute(&mut *connection)
    .await
    .map(|_done| ())
    .map_err(translate_reference)
}

/// Rebuilds the routes of `rows`, in their order.
fn restore_all(rows: Vec<RouteRow>) -> Result<Vec<Route>, RepositoryError> {
    rows.into_iter()
        .map(|row| restore(row).map(Route::restore))
        .collect()
}

/// The methods of the stored texts; a text that is not a method is unusable data.
fn methods_of(texts: &[String]) -> Result<Vec<HttpMethod>, RepositoryError> {
    texts
        .iter()
        .map(|text| HttpMethod::parse(text).ok_or_else(|| unusable_field("methods")))
        .collect()
}

/// The flags of the stored values `graphql`, `streaming` and `anonymous`, in this order.
fn flags_of(values: &[bool]) -> Result<RouteFlags, RepositoryError> {
    let [graphql, streaming, anonymous] = *values else {
        return Err(unusable_field("flags"));
    };
    Ok(RouteFlags::default()
        .with(RouteFlag::Graphql, graphql)
        .with(RouteFlag::Streaming, streaming)
        .with(RouteFlag::Anonymous, anonymous))
}

/// Rebuilds one stored route through the value objects.
fn restore(row: RouteRow) -> Result<RouteParts, RepositoryError> {
    let draft = RouteDraft {
        host: row.host,
        methods: methods_of(&row.methods)?,
        path_pattern: row.path_pattern,
        service: row.service,
        upstream_id: UpstreamId::from_uuid(Uuid::from_uuid(row.upstream_id)),
        flags: flags_of(&row.flags)?,
        enforcement: EnforcementMode::parse(&row.enforcement)
            .ok_or_else(|| unusable_field("enforcement"))?,
        body_limit: row.body_limit,
        request_timeout_ms: row.request_timeout_ms,
        idle_timeout_ms: row.idle_timeout_ms,
        retry: RetryPolicy::parse(&row.retry).ok_or_else(|| unusable_field("retry"))?,
        rate_policies: row
            .rate_policies
            .into_iter()
            .map(|id| RatePolicyId::from_uuid(Uuid::from_uuid(id)))
            .collect(),
        cors: row
            .cors
            .as_deref()
            .map(cors_from_json)
            .transpose()
            .map_err(unusable_value)?,
    };
    Ok(RouteParts {
        id: RouteId::from_uuid(Uuid::from_uuid(row.id)),
        fields: RouteFields::new(&draft).map_err(|_violations| unusable_field("route"))?,
        system: row.system,
        version: EntityVersion::new(row.version).map_err(unusable_value)?,
        created_at: SystemTime::from(row.created_at),
        updated_at: SystemTime::from(row.updated_at),
        deleted_at: None,
    })
}

#[async_trait::async_trait]
impl RouteRepository for PgRouteRepository {
    async fn find_by_id(&self, id: RouteId) -> Result<Option<Route>, RepositoryError> {
        self.find_one(id).await
    }

    async fn find_page(&self, query: &RoutePageQuery) -> Result<Vec<Route>, RepositoryError> {
        self.select_page(query).await
    }

    async fn find_by_host(&self, host: &RouteHost) -> Result<Vec<Route>, RepositoryError> {
        self.select_by_host(host).await
    }

    async fn count_by_upstream(&self, upstream: UpstreamId) -> Result<u64, RepositoryError> {
        self.count_upstream(upstream).await
    }

    async fn count_by_rate_policy(&self, policy: RatePolicyId) -> Result<u64, RepositoryError> {
        self.count_rate_policy(policy).await
    }
}

#[cfg(test)]
mod tests;
