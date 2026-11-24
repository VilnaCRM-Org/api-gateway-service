//! `RouteSetDiff`: what replacing the full route set of one host changes (FR-58).

use std::collections::BTreeMap;

use crate::policy::route_revocation_rule::{RouteChangeClass, RouteRevocationRule};
use crate::route::RouteParts;
use crate::route::fields::RouteFields;
use crate::value_object::http_method::HttpMethod;

/// A route that a set keeps under the same methods and path pattern and whose configuration
/// differs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedRoute {
    /// The stored route.
    pub before: RouteParts,
    /// The configuration the set asks for.
    pub after: RouteFields,
}

impl ChangedRoute {
    /// The names of the properties that the change touches.
    #[must_use]
    pub fn changed_fields(&self) -> Vec<&'static str> {
        self.before.fields.changed_fields(&self.after)
    }
}

/// The difference between the stored routes of a host and a declared set.
///
/// A declared route is the same route as a stored one when it serves the same methods under the
/// same path pattern; any other member that differs makes it a changed route. A stored route that
/// the set does not declare is removed, a declared route without a stored one is added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSetDiff {
    added: Vec<RouteFields>,
    changed: Vec<ChangedRoute>,
    removed: Vec<RouteParts>,
    unchanged: usize,
}

/// The identity of a route inside a set: its methods and its path pattern.
type RouteKey = (Vec<HttpMethod>, String);

/// The identity of the route with `fields`.
fn key_of(fields: &RouteFields) -> RouteKey {
    (
        fields.methods().to_vec(),
        fields.path_pattern().as_str().to_owned(),
    )
}

impl RouteSetDiff {
    /// The difference between the `stored` routes of a host and the `declared` set; added and
    /// changed routes keep the order of the set, removed routes the order of their identity.
    #[must_use]
    pub fn between(stored: &[RouteParts], declared: Vec<RouteFields>) -> Self {
        let mut remaining: BTreeMap<RouteKey, &RouteParts> = stored
            .iter()
            .map(|route| (key_of(&route.fields), route))
            .collect();
        let mut added = Vec::new();
        let mut changed = Vec::new();
        let mut unchanged = 0_usize;
        for fields in declared {
            match remaining.remove(&key_of(&fields)) {
                None => added.push(fields),
                Some(route) if route.fields == fields => unchanged = unchanged.saturating_add(1),
                Some(route) => changed.push(ChangedRoute {
                    before: route.clone(),
                    after: fields,
                }),
            }
        }
        Self {
            added,
            changed,
            removed: remaining.into_values().cloned().collect(),
            unchanged,
        }
    }

    /// The routes the set creates.
    #[must_use]
    pub fn added(&self) -> &[RouteFields] {
        &self.added
    }

    /// The routes the set updates.
    #[must_use]
    pub fn changed(&self) -> &[ChangedRoute] {
        &self.changed
    }

    /// The routes the set deletes.
    #[must_use]
    pub fn removed(&self) -> &[RouteParts] {
        &self.removed
    }

    /// The number of routes the set keeps as they are.
    #[must_use]
    pub const fn unchanged(&self) -> usize {
        self.unchanged
    }

    /// Whether the set changes nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.added.is_empty() && self.changed.is_empty() && self.removed.is_empty()
    }

    /// The class of the whole set: a revocation when it deletes a route, clears `anonymous` or
    /// moves `enforcement` from `audit` to `enforce`.
    #[must_use]
    pub fn class(&self) -> RouteChangeClass {
        let deletion = self
            .removed
            .first()
            .map(|_route| RouteRevocationRule::classify_delete());
        let revoking = self
            .changed
            .iter()
            .map(|route| RouteRevocationRule::classify_update(&route.before.fields, &route.after))
            .chain(deletion)
            .any(|class| class == RouteChangeClass::Revocation);
        if revoking {
            RouteChangeClass::Revocation
        } else {
            RouteChangeClass::Standard
        }
    }
}

#[cfg(test)]
mod tests;
