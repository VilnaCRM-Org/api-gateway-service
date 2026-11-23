//! The write of one upstream, route or rate policy that a change hands to the unit of work.

use crate::rate_policy::statement::RatePolicyStatement;
use crate::route::statement::RouteStatement;
use crate::state::key::StateKey;
use crate::upstream::statement::UpstreamStatement;
use crate::value_object::change_statement::ChangeStatement;

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
