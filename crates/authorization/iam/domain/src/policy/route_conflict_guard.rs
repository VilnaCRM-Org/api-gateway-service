//! `RouteConflictGuard`: no two routes of a host conflict (FR-56).

use crate::error::RouteConflict;
use crate::route::RouteParts;

/// Checks routes against each other.
///
/// Two routes of one host conflict when they have the same path pattern shape and share a method,
/// and when an anonymous route has a broader pattern than a protected route, through a parameter
/// or a catch-all segment: the anonymous route would shadow the protected one.
#[derive(Debug, Clone, Copy)]
pub struct RouteConflictGuard;

impl RouteConflictGuard {
    /// Checks two routes of the same host against each other; the answer does not depend on the
    /// order of the arguments.
    ///
    /// # Errors
    ///
    /// The [`RouteConflict`] of the pair; none for routes on different hosts and for a route with
    /// itself.
    pub fn check_pair(first: &RouteParts, second: &RouteParts) -> Result<(), RouteConflict> {
        if first.id == second.id || first.fields.host() != second.fields.host() {
            return Ok(());
        }
        if first
            .fields
            .path_pattern()
            .same_shape(second.fields.path_pattern())
            && first.fields.shares_a_method_with(&second.fields)
        {
            return Err(RouteConflict::SamePattern {
                first: first.id,
                second: second.id,
            });
        }
        Self::check_shadow(first, second).and_then(|()| Self::check_shadow(second, first))
    }

    /// Checks a route that is about to be saved against the routes already stored.
    ///
    /// # Errors
    ///
    /// The [`RouteConflict`] of the first stored route that conflicts with `candidate`.
    pub fn check_candidate(
        candidate: &RouteParts,
        stored: &[RouteParts],
    ) -> Result<(), RouteConflict> {
        stored
            .iter()
            .try_for_each(|route| Self::check_pair(candidate, route))
    }

    /// Validates a full host configuration as a set: every pair must be free of conflicts.
    ///
    /// # Errors
    ///
    /// The [`RouteConflict`] of the first conflicting pair, in the order of `routes`.
    pub fn check_set(routes: &[RouteParts]) -> Result<(), RouteConflict> {
        routes.iter().enumerate().try_for_each(|(index, route)| {
            let later = routes.get(index.saturating_add(1)..).unwrap_or_default();
            Self::check_candidate(route, later)
        })
    }

    /// Whether `anonymous` is an anonymous route that shadows the protected route `protected`.
    fn check_shadow(anonymous: &RouteParts, protected: &RouteParts) -> Result<(), RouteConflict> {
        let shadows = anonymous.fields.flags().anonymous()
            && !protected.fields.flags().anonymous()
            && anonymous
                .fields
                .path_pattern()
                .is_broader_than(protected.fields.path_pattern());
        if shadows {
            return Err(RouteConflict::AnonymousShadow {
                anonymous: anonymous.id,
                protected: protected.id,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
