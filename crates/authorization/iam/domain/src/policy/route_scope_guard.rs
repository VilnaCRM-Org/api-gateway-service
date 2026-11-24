//! `RouteScopeGuard`: who may change the routes and upstreams of a catalogue service (FR-64).

use std::time::SystemTime;

use crate::policy::compiled_role_set::CompiledRoleSet;
use crate::policy::subject_policy::SubjectPolicy;
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_key::PermissionKey;
use crate::value_object::reserved_permission::{ReservedPermission, ServiceScope};
use crate::value_object::service_name::ServiceName;

/// The refusal of a change of a route or an upstream.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RouteScopeRefused {
    /// The entry belongs to the `iam` service, which the API never changes; 409 `system_entry`.
    #[error("Entries of the iam service cannot be changed.")]
    IamService,
    /// The entry is a system entry, which the API never changes; 409 `system_entry`.
    #[error("System entries cannot be changed.")]
    SystemEntry,
    /// The route names another service than its upstream's catalogue service; 422.
    #[error(
        "The route service {route} differs from the catalogue service {upstream} of its upstream."
    )]
    ServiceMismatch {
        /// The service of the route.
        route: ServiceName,
        /// The catalogue service of the upstream.
        upstream: ServiceName,
    },
    /// The principal holds neither `iam:route:{service}` nor `iam:route:*`; 403.
    #[error("Changing entries of the service {service} needs iam:route:{service} or iam:route:*.")]
    Missing {
        /// The service whose key is missing.
        service: ServiceName,
    },
}

impl RouteScopeRefused {
    /// The machine-readable refusal code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::IamService | Self::SystemEntry => "system_entry",
            Self::ServiceMismatch { .. } => "service_mismatch",
            Self::Missing { .. } => "forbidden",
        }
    }
}

/// Checks the principal of a change of a route or an upstream against the entry's service.
#[derive(Debug, Clone, Copy)]
pub struct RouteScopeGuard;

impl RouteScopeGuard {
    /// Checks the creation, the change or the deletion of an upstream whose catalogue service is
    /// `service`.
    ///
    /// # Errors
    ///
    /// [`RouteScopeRefused::IamService`] and [`RouteScopeRefused::SystemEntry`] for entries that
    /// nobody may change, then [`RouteScopeRefused::Missing`] for a principal without the key.
    pub fn check_upstream(
        held: &CompiledRoleSet,
        service: &ServiceName,
        system: bool,
    ) -> Result<(), RouteScopeRefused> {
        Self::check_changeable(service, system)?;
        Self::check_held(held, service)
    }

    /// Checks the creation, the change or the deletion of a route of `service` whose upstream
    /// serves `upstream_service`.
    ///
    /// # Errors
    ///
    /// The refusals of [`RouteScopeGuard::check_upstream`], with
    /// [`RouteScopeRefused::ServiceMismatch`] before [`RouteScopeRefused::Missing`].
    pub fn check_route(
        held: &CompiledRoleSet,
        service: &ServiceName,
        system: bool,
        upstream_service: &ServiceName,
    ) -> Result<(), RouteScopeRefused> {
        Self::check_changeable(service, system)?;
        if service != upstream_service {
            return Err(RouteScopeRefused::ServiceMismatch {
                route: service.clone(),
                upstream: upstream_service.clone(),
            });
        }
        Self::check_held(held, service)
    }

    /// Lets a change of an entry of `service` through when the actor's policy holds
    /// `iam:route:{service}` or `iam:route:*` at global scope at `now`; the application has
    /// refused the entries that nobody may change before it asks.
    ///
    /// # Errors
    ///
    /// [`RouteScopeRefused::Missing`] for an actor without the key.
    pub fn check_policy(
        policy: &SubjectPolicy,
        now: SystemTime,
        service: &ServiceName,
    ) -> Result<(), RouteScopeRefused> {
        let key = ReservedPermission::Route(ServiceScope::Service(service.clone()));
        if policy.holds_reserved(&key, now) {
            Ok(())
        } else {
            Err(RouteScopeRefused::Missing {
                service: service.clone(),
            })
        }
    }

    /// Refuses the entries that nobody may change: those of the `iam` service and `system`
    /// entries.
    ///
    /// # Errors
    ///
    /// [`RouteScopeRefused::IamService`] and [`RouteScopeRefused::SystemEntry`].
    pub fn check_changeable(service: &ServiceName, system: bool) -> Result<(), RouteScopeRefused> {
        if service.is_iam() {
            return Err(RouteScopeRefused::IamService);
        }
        if system {
            return Err(RouteScopeRefused::SystemEntry);
        }
        Ok(())
    }

    /// Refuses a principal that holds neither `iam:route:{service}` nor `iam:route:*`.
    fn check_held(held: &CompiledRoleSet, service: &ServiceName) -> Result<(), RouteScopeRefused> {
        let key = PermissionKey::Reserved(ReservedPermission::Route(ServiceScope::Service(
            service.clone(),
        )));
        if held.holds(&key, PermissionFlags::NONE) {
            Ok(())
        } else {
            Err(RouteScopeRefused::Missing {
                service: service.clone(),
            })
        }
    }
}

#[cfg(test)]
mod tests;
