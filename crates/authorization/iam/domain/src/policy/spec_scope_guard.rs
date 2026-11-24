//! `SpecScopeGuard`: who may load, activate or retire the specifications of a service (FR-30,
//! FR-34, FR-36, FR-38).

use std::time::SystemTime;

use crate::policy::subject_policy::SubjectPolicy;
use crate::value_object::reserved_permission::{ReservedPermission, ServiceScope};
use crate::value_object::service_name::ServiceName;

/// The refusal of a change of a specification; the application answers 403 and audits the
/// attempt.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("Changing specifications of this service needs {key}, held at global scope.")]
pub struct SpecScopeDenied {
    /// The first reserved key the actor lacks.
    pub key: ReservedPermission,
}

impl SpecScopeDenied {
    /// The machine-readable refusal code, recorded as the reason of the rejected audit record.
    pub const CODE: &'static str = "spec_scope.denied";
}

/// The rule for loading, activating or retiring a specification of service `s`.
///
/// It needs `iam:spec:s` or `iam:spec:*` at global scope (`iam:spec:*` never covers `iam`), and a
/// confirmed flag downgrade also needs `iam:grant:sensitive`.
#[derive(Debug, Clone, Copy)]
pub struct SpecScopeGuard;

impl SpecScopeGuard {
    /// The reserved keys that a change of a specification of `service` needs.
    #[must_use]
    pub fn required(service: &ServiceName, flag_downgrade: bool) -> Vec<ReservedPermission> {
        let mut required = vec![ReservedPermission::Spec(ServiceScope::Service(
            service.clone(),
        ))];
        if flag_downgrade {
            required.push(ReservedPermission::GrantSensitive);
        }
        required
    }

    /// Lets the change through when the actor's policy holds every key it needs at global scope at
    /// `now`.
    ///
    /// # Errors
    ///
    /// [`SpecScopeDenied`] with the first key the actor lacks.
    pub fn check(
        policy: &SubjectPolicy,
        now: SystemTime,
        service: &ServiceName,
        flag_downgrade: bool,
    ) -> Result<(), SpecScopeDenied> {
        Self::required(service, flag_downgrade)
            .into_iter()
            .find(|key| !policy.holds_reserved(key, now))
            .map_or(Ok(()), |key| Err(SpecScopeDenied { key }))
    }
}

#[cfg(test)]
mod tests;
