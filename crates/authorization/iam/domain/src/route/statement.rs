//! The write of one route that a change hands to the unit of work.

use crate::route::{Route, RouteParts};
use crate::value_object::entity_version::EntityVersion;

/// The write of one route: an insert, or an update guarded by the version the change read. A
/// deletion is an update of a route that carries its deletion time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteStatement {
    route: RouteParts,
    expected: Option<EntityVersion>,
}

impl RouteStatement {
    /// The insert of a new route; a stored route with the same identifier refuses it as a
    /// duplicate, and an upstream or rate policy that is not stored refuses it as a conflict.
    #[must_use]
    pub fn insert(route: &Route) -> Self {
        Self {
            route: route.parts().clone(),
            expected: None,
        }
    }

    /// The update of a stored route that is not deleted and still holds the version `expected`;
    /// any other stored state refuses it as a conflict.
    #[must_use]
    pub fn update(route: &Route, expected: EntityVersion) -> Self {
        Self {
            route: route.parts().clone(),
            expected: Some(expected),
        }
    }

    /// The state of the route to store.
    #[must_use]
    pub const fn route(&self) -> &RouteParts {
        &self.route
    }

    /// The version the stored route must hold; `None` for an insert.
    #[must_use]
    pub const fn expected(&self) -> Option<EntityVersion> {
        self.expected
    }
}

#[cfg(test)]
mod tests;
