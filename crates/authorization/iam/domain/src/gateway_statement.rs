//! The write of one upstream, route or rate policy that a change hands to the unit of work.

use crate::rate_policy::statement::RatePolicyStatement;
use crate::route::RouteParts;
use crate::route::statement::RouteStatement;
use crate::state::key::StateKey;
use crate::upstream::statement::UpstreamStatement;
use crate::value_object::change_statement::ChangeStatement;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::identifier::{RatePolicyId, UpstreamId};
use crate::value_object::route_host::RouteHost;
use crate::value_object::service_name::ServiceName;

/// One write of the gateway configuration: an upstream, a route with its rate policies, or a rate
/// policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayStatement {
    /// Insert a new upstream, or update a stored upstream at the expected version; a duplicate id
    /// or a name that an upstream that is not deleted holds refuses the change as a duplicate and a
    /// stale or deleted stored upstream as a conflict.
    Upstream(UpstreamStatement),
    /// Insert a new route with its rate policies, or update a stored route at the expected
    /// version; a duplicate id refuses the change as a duplicate, a missing upstream or rate policy
    /// and a stale or deleted stored route as a conflict.
    Route(RouteStatement),
    /// Insert a new rate policy, or update a stored rate policy at the expected version; a
    /// duplicate id or a name that a rate policy that is not deleted holds refuses the change as a
    /// duplicate and a stale or deleted stored rate policy as a conflict.
    RatePolicy(RatePolicyStatement),
}

/// A condition of the gateway configuration that the unit of work evaluates inside the
/// transaction of the change.
///
/// The unit of work evaluates it after it locked the policy epoch and before the writes of the
/// change. Every write of the configuration takes the same lock, so a condition that holds here
/// still holds when the change commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayPrecondition {
    /// No route that is not deleted references the upstream; a reference refuses the change as
    /// [`ReferencedByRoute`](crate::error::ReferencedByRoute).
    UpstreamUnreferenced(UpstreamId),
    /// No route that is not deleted names the rate policy; a reference refuses the change as
    /// [`ReferencedByRoute`](crate::error::ReferencedByRoute).
    RatePolicyUnreferenced(RatePolicyId),
    /// The upstream of a route is stored, is not deleted and serves `service`, and every rate
    /// policy of the route is stored and not deleted; anything else refuses the change as a
    /// conflict.
    RouteTargets {
        /// The upstream the route forwards to.
        upstream_id: UpstreamId,
        /// The catalogue service of the route, which the upstream must serve.
        service: ServiceName,
        /// The rate policies the route names.
        rate_policies: Vec<RatePolicyId>,
    },
    /// The routes of the host of `candidate`, read again, conflict with no pair and compile into
    /// a route table together with `candidate`; a conflict refuses the change as
    /// [`RouteConflict`](crate::error::RouteConflict).
    RouteTable(Box<RouteParts>),
    /// The stored route set of `host`, read again, still has `version`: no route of the host was
    /// created, changed or deleted since the plan of a whole-set change read it; anything else
    /// refuses the change as a conflict.
    RouteSetVersion {
        /// The host whose set the change replaces.
        host: RouteHost,
        /// The version the plan was made against.
        version: EntityVersion,
    },
}

impl From<GatewayPrecondition> for ChangeStatement {
    fn from(precondition: GatewayPrecondition) -> Self {
        Self::ExpectGateway(Box::new(precondition))
    }
}

impl GatewayStatement {
    /// The key of the state record that the write changes: `upstream/<name>`, `route/<id>` or
    /// `ratepolicy/<id>`.
    #[must_use]
    pub fn state_key(&self) -> StateKey {
        match self {
            Self::Upstream(statement) => StateKey::Upstream(statement.upstream().name.clone()),
            Self::Route(statement) => StateKey::Route(statement.route().id),
            Self::RatePolicy(statement) => StateKey::RatePolicy(statement.rate_policy().id),
        }
    }
}

impl From<UpstreamStatement> for ChangeStatement {
    fn from(statement: UpstreamStatement) -> Self {
        Self::SaveGateway(Box::new(GatewayStatement::Upstream(statement)))
    }
}

impl From<RouteStatement> for ChangeStatement {
    fn from(statement: RouteStatement) -> Self {
        Self::SaveGateway(Box::new(GatewayStatement::Route(statement)))
    }
}

impl From<RatePolicyStatement> for ChangeStatement {
    fn from(statement: RatePolicyStatement) -> Self {
        Self::SaveGateway(Box::new(GatewayStatement::RatePolicy(statement)))
    }
}

#[cfg(test)]
mod tests;
