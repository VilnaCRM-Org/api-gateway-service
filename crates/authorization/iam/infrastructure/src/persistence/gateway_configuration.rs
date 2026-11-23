//! Runs the statements of the gateway configuration that a change hands to the unit of work.

use iam_domain::{GatewayStatement, RepositoryError};
use sqlx::PgConnection;

use crate::persistence::{rate_policy, route, upstream};

/// Runs one upstream, route or rate policy statement inside the caller's transaction. A failure
/// leaves the rollback to the caller.
///
/// # Errors
///
/// The errors of [`upstream::save_within`], [`route::save_within`] and
/// [`rate_policy::save_within`].
pub async fn save_within(
    connection: &mut PgConnection,
    statement: &GatewayStatement,
) -> Result<(), RepositoryError> {
    match statement {
        GatewayStatement::Upstream(upstream) => upstream::save_within(connection, upstream).await,
        GatewayStatement::Route(route) => route::save_within(connection, route).await,
        GatewayStatement::RatePolicy(policy) => rate_policy::save_within(connection, policy).await,
    }
}
