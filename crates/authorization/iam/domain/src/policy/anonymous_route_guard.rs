//! `AnonymousRouteGuard`: only a holder of `iam:route:anonymous` makes a route anonymous or
//! audit-only, or changes either flag (FR-57).

use std::time::SystemTime;

use crate::policy::compiled_role_set::CompiledRoleSet;
use crate::policy::subject_policy::SubjectPolicy;
use crate::route::fields::RouteFields;
use crate::route::settings::EnforcementMode;
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_key::PermissionKey;
use crate::value_object::reserved_permission::ReservedPermission;

/// The refusal of a change that needs `iam:route:anonymous`; the application answers 403.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "Making a route anonymous or audit-only, or changing either flag, needs iam:route:anonymous."
)]
pub struct AnonymousRouteRefused;

impl AnonymousRouteRefused {
    /// The machine-readable refusal code.
    pub const CODE: &'static str = "anonymous_route_forbidden";
}

/// Checks the principal of a route change against the anonymous and audit flags.
#[derive(Debug, Clone, Copy)]
pub struct AnonymousRouteGuard;

impl AnonymousRouteGuard {
    /// Checks the creation of a route: a route that is anonymous or audit-only needs the key.
    ///
    /// # Errors
    ///
    /// [`AnonymousRouteRefused`] when the route needs the key and `held` does not hold it.
    pub fn check_create(
        held: &CompiledRoleSet,
        fields: &RouteFields,
    ) -> Result<(), AnonymousRouteRefused> {
        Self::require(held, Self::needs_key_on_create(fields))
    }

    /// Whether creating a route with these fields needs the key: the route is anonymous or
    /// audit-only.
    #[must_use]
    pub fn needs_key_on_create(fields: &RouteFields) -> bool {
        fields.flags().anonymous() || fields.enforcement() == EnforcementMode::Audit
    }

    /// Whether an update needs the key: it changes `anonymous` or `enforcement`, in either
    /// direction.
    #[must_use]
    pub fn needs_key_on_update(before: &RouteFields, after: &RouteFields) -> bool {
        before.flags().anonymous() != after.flags().anonymous()
            || before.enforcement() != after.enforcement()
    }

    /// Lets a change that needs the key through when the actor's policy holds
    /// `iam:route:anonymous` at global scope at `now`.
    ///
    /// # Errors
    ///
    /// [`AnonymousRouteRefused`] for an actor without the key.
    pub fn check_policy(
        policy: &SubjectPolicy,
        now: SystemTime,
    ) -> Result<(), AnonymousRouteRefused> {
        if policy.holds_reserved(&ReservedPermission::RouteAnonymous, now) {
            Ok(())
        } else {
            Err(AnonymousRouteRefused)
        }
    }

    /// Checks an update: changing `anonymous` or `enforcement` in either direction needs the key.
    ///
    /// # Errors
    ///
    /// [`AnonymousRouteRefused`] when the update changes either flag and `held` does not hold the
    /// key.
    pub fn check_update(
        held: &CompiledRoleSet,
        before: &RouteFields,
        after: &RouteFields,
    ) -> Result<(), AnonymousRouteRefused> {
        Self::require(held, Self::needs_key_on_update(before, after))
    }

    fn require(held: &CompiledRoleSet, needs_key: bool) -> Result<(), AnonymousRouteRefused> {
        let key = PermissionKey::Reserved(ReservedPermission::RouteAnonymous);
        if needs_key && !held.holds(&key, PermissionFlags::NONE) {
            return Err(AnonymousRouteRefused);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
