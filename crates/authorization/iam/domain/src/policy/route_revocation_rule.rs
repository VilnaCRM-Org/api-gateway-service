//! The revocation-class rule for routes: which changes take access away and so need the stronger
//! handling of a revocation (FR-57).

use crate::route::fields::RouteFields;
use crate::route::settings::EnforcementMode;

/// The class of a route change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteChangeClass {
    /// The change takes no access away.
    Standard,
    /// The change takes access away: clearing `anonymous`, moving `enforcement` from `audit` to
    /// `enforce`, or deleting the route.
    Revocation,
}

/// Classifies route changes.
#[derive(Debug, Clone, Copy)]
pub struct RouteRevocationRule;

impl RouteRevocationRule {
    /// The class of an update from `before` to `after`.
    #[must_use]
    pub fn classify_update(before: &RouteFields, after: &RouteFields) -> RouteChangeClass {
        let anonymous_cleared = before.flags().anonymous() && !after.flags().anonymous();
        let enforced = before.enforcement() == EnforcementMode::Audit
            && after.enforcement() == EnforcementMode::Enforce;
        if anonymous_cleared || enforced {
            RouteChangeClass::Revocation
        } else {
            RouteChangeClass::Standard
        }
    }

    /// The class of a deletion: always a revocation.
    #[must_use]
    pub const fn classify_delete() -> RouteChangeClass {
        RouteChangeClass::Revocation
    }
}

#[cfg(test)]
mod tests;
