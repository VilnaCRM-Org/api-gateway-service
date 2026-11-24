//! Evaluates the preconditions of the gateway configuration that a change hands to the unit of
//! work: the reference checks of a deletion and the checks of the route that a change writes.
//!
//! The unit of work calls this module inside the transaction of the change, after it locked the
//! policy epoch row. Every write of the gateway configuration takes that lock, so the answers
//! stay true until the transaction ends. The statements are checked at run time, so the offline
//! query metadata does not hold them.

use std::collections::BTreeSet;

use iam_domain::{
    EntityVersion, GatewayPrecondition, RatePolicyId, ReferencedByRoute, RepositoryError,
    RouteConflictGuard, RouteHost, RouteParts, RouteSetVersion, RouteTableCompiler, UpstreamId,
};
use sqlx::PgConnection;
use sqlx::types::Uuid as SqlUuid;

use crate::persistence::role::translate;
use crate::persistence::route::select_parts_by_host;
use crate::persistence::stored::count_of;

/// Evaluates one precondition inside the caller's transaction, with `compiler` for the route
/// table. A failure leaves the rollback to the caller.
///
/// # Errors
///
/// [`RepositoryError::ReferencedByRoute`] when a route references the entry,
/// [`RepositoryError::Conflict`] when the upstream or a rate policy of a route is not stored,
/// is deleted or does not serve the route, [`RepositoryError::RouteTable`] when the route
/// table of the host conflicts or cannot be compiled, and [`RepositoryError::Unavailable`] when
/// the storage fails.
pub async fn check_within(
    connection: &mut PgConnection,
    precondition: &GatewayPrecondition,
    compiler: &dyn RouteTableCompiler,
) -> Result<(), RepositoryError> {
    match precondition {
        GatewayPrecondition::UpstreamUnreferenced(upstream) => {
            upstream_unreferenced(connection, *upstream).await
        }
        GatewayPrecondition::RatePolicyUnreferenced(policy) => {
            rate_policy_unreferenced(connection, *policy).await
        }
        GatewayPrecondition::RouteTargets {
            upstream_id,
            service,
            rate_policies,
        } => route_targets(connection, *upstream_id, service.as_str(), rate_policies).await,
        GatewayPrecondition::RouteTable(candidate) => {
            route_table(connection, candidate, compiler).await
        }
        GatewayPrecondition::RouteSetVersion { host, version } => {
            route_set_version(connection, host, *version).await
        }
    }
}

/// No route that is not deleted forwards to the upstream.
async fn upstream_unreferenced(
    connection: &mut PgConnection,
    upstream: UpstreamId,
) -> Result<(), RepositoryError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM iam_routes WHERE upstream_id = $1 AND deleted_at IS NULL",
    )
    .bind(upstream.as_uuid().as_uuid())
    .fetch_one(&mut *connection)
    .await
    .map_err(translate)?;
    referenced(count)
}

/// No route that is not deleted names the rate policy.
async fn rate_policy_unreferenced(
    connection: &mut PgConnection,
    policy: RatePolicyId,
) -> Result<(), RepositoryError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM iam_route_rate_policies AS applied
        JOIN iam_routes AS routes ON routes.id = applied.route_id
        WHERE applied.rate_policy_id = $1 AND routes.deleted_at IS NULL",
    )
    .bind(policy.as_uuid().as_uuid())
    .fetch_one(&mut *connection)
    .await
    .map_err(translate)?;
    referenced(count)
}

/// The refusal that a count of references above zero is.
fn referenced(count: i64) -> Result<(), RepositoryError> {
    ReferencedByRoute::check(count_of(count)?).map_err(RepositoryError::ReferencedByRoute)
}

/// The upstream is stored, is not deleted and serves `service`, and every rate policy is stored
/// and not deleted.
async fn route_targets(
    connection: &mut PgConnection,
    upstream: UpstreamId,
    service: &str,
    rate_policies: &[RatePolicyId],
) -> Result<(), RepositoryError> {
    let catalog: Option<String> = sqlx::query_scalar(
        "SELECT catalog_service FROM iam_upstreams WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(upstream.as_uuid().as_uuid())
    .fetch_optional(&mut *connection)
    .await
    .map_err(translate)?;
    if catalog.as_deref() != Some(service) {
        return Err(RepositoryError::Conflict);
    }
    let wanted: BTreeSet<SqlUuid> = rate_policies
        .iter()
        .map(|policy| policy.as_uuid().as_uuid())
        .collect();
    let stored: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM iam_rate_policies WHERE id = ANY($1::uuid[]) AND deleted_at IS NULL",
    )
    .bind(wanted.iter().copied().collect::<Vec<_>>())
    .fetch_one(&mut *connection)
    .await
    .map_err(translate)?;
    if count_of(stored)? == u64::try_from(wanted.len()).unwrap_or(u64::MAX) {
        Ok(())
    } else {
        Err(RepositoryError::Conflict)
    }
}

/// The routes of the host of `candidate`, read again in this transaction, conflict with no pair
/// and compile into a route table together with `candidate`.
async fn route_table(
    connection: &mut PgConnection,
    candidate: &RouteParts,
    compiler: &dyn RouteTableCompiler,
) -> Result<(), RepositoryError> {
    let host = candidate.fields.host();
    let mut table: Vec<RouteParts> = select_parts_by_host(&mut *connection, host)
        .await?
        .into_iter()
        .filter(|route| route.id != candidate.id)
        .collect();
    RouteConflictGuard::check_candidate(candidate, &table).map_err(RepositoryError::RouteTable)?;
    table.push(candidate.clone());
    compiler
        .compile(host, &table)
        .map(|_matcher| ())
        .map_err(RepositoryError::RouteTable)
}

/// The routes of `host`, read again in this transaction, still have the version the plan read.
async fn route_set_version(
    connection: &mut PgConnection,
    host: &RouteHost,
    expected: EntityVersion,
) -> Result<(), RepositoryError> {
    let stored = select_parts_by_host(&mut *connection, host).await?;
    if RouteSetVersion::of(&stored) == expected {
        Ok(())
    } else {
        Err(RepositoryError::Conflict)
    }
}
