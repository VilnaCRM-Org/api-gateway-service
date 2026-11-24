//! The dry run of a declarative route configuration: the diff against the stored set, with
//! nothing written (FR-58).

use std::sync::Arc;

use iam_domain::{ActorRef, EntityVersion, RouteDraft, RouteHost, RouteSetDiff};
use shared_domain::{Clock, Query, QueryHandler, UuidGenerator};

use crate::command::gateway_audit::SystemEntryRefusal;
use crate::command::route_checks::RoutePorts;
use crate::command::route_configuration_plan::{
    AUDIT_ACTION, AUDIT_KIND, RouteConfigurationPlanner, RouteSetRequest,
};
use crate::error::IamError;

/// Asks what `routes` would change on the host `host`, when the stored set has the version
/// `expected`.
#[derive(Debug, Clone)]
pub struct PreviewRouteConfigurationQuery {
    /// The host whose routes the set would replace.
    pub host: String,
    /// The declared routes; the host of a draft is replaced by `host`.
    pub routes: Vec<RouteDraft>,
    /// The version of the stored set that the caller read.
    pub expected: EntityVersion,
    /// Who asks; the refusal of a route that IAM manages itself is audited for this actor.
    pub actor: ActorRef,
}

/// What a set would change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteConfigurationPreview {
    /// The host.
    pub host: RouteHost,
    /// The version of the stored set.
    pub version: EntityVersion,
    /// The number of routes the host would hold.
    pub route_count: usize,
    /// The routes the set would create, update and delete.
    pub diff: RouteSetDiff,
}

impl Query for PreviewRouteConfigurationQuery {
    type Output = RouteConfigurationPreview;
    type Error = IamError;
    const NAME: &'static str = "PreviewRouteConfigurationQuery";
}

/// Handles [`PreviewRouteConfigurationQuery`].
///
/// It runs every check that the application of the set runs, including the route keys the guarded
/// unit of work checks at the commit (`iam:route:{service}` or `iam:route:*` for every service of
/// the set, `iam:route:anonymous` when the set needs it), so that a dry run is refused exactly
/// when the application would be (403, offered to the buffer of the audit log), and commits
/// nothing.
#[derive(Debug)]
pub struct PreviewRouteConfigurationQueryHandler {
    ports: RoutePorts,
    max_routes: usize,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl PreviewRouteConfigurationQueryHandler {
    /// A handler over its ports, the largest set it accepts (`ROUTE_CONFIGURATION_MAX_ROUTES`),
    /// the clock and the identifier source.
    #[must_use]
    pub const fn new(
        ports: RoutePorts,
        max_routes: usize,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            ports,
            max_routes,
            clock,
            uuid_generator,
        }
    }

    async fn preview(
        &self,
        query: PreviewRouteConfigurationQuery,
    ) -> Result<RouteConfigurationPreview, IamError> {
        let now = self.clock.now();
        let planner = RouteConfigurationPlanner::new(
            &self.ports,
            self.max_routes,
            self.uuid_generator.as_ref(),
        );
        let plan = planner
            .plan(RouteSetRequest {
                host: &query.host,
                routes: query.routes,
                expected: query.expected,
                actor: &query.actor,
                occurred_at: now,
            })
            .await?;
        self.ports
            .admit_set(
                &plan.services,
                plan.anonymous_key,
                SystemEntryRefusal {
                    action: AUDIT_ACTION,
                    kind: AUDIT_KIND,
                    target_id: plan.host.to_string(),
                    actor: &query.actor,
                    occurred_at: now,
                },
            )
            .await?;
        Ok(RouteConfigurationPreview {
            host: plan.host,
            version: plan.version,
            route_count: plan.table.len(),
            diff: plan.diff,
        })
    }
}

#[async_trait::async_trait]
impl QueryHandler<PreviewRouteConfigurationQuery> for PreviewRouteConfigurationQueryHandler {
    async fn handle(
        &self,
        query: PreviewRouteConfigurationQuery,
    ) -> Result<RouteConfigurationPreview, IamError> {
        self.preview(query).await
    }
}

#[cfg(test)]
mod tests;
