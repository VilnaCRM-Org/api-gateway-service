//! `EscalationGuard`: nobody grants, assigns or changes more than the administrative rights it
//! holds itself (FR-24, FR-25).

use std::collections::BTreeSet;
use std::time::SystemTime;

use crate::policy::subject_policy::SubjectPolicy;
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::reserved_permission::{ReservedPermission, ServiceScope};
use crate::value_object::service_name::ServiceName;
use crate::value_object::subject::SubjectRef;

/// What a grant needs besides the key of its service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GrantedKind {
    /// An exact key that is not sensitive, or a reserved key.
    Plain,
    /// An exact key whose catalogue entry is sensitive: it also needs `iam:grant:sensitive`.
    Sensitive,
    /// A wildcard pattern: it also needs `iam:grant:wildcard`.
    Wildcard,
}

/// One grant that a change gives to a role, reduced to what the guard decides on.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GrantedKey {
    service: ServiceName,
    kind: GrantedKind,
}

impl GrantedKey {
    /// A grant of the service of the given kind.
    #[must_use]
    pub const fn new(service: ServiceName, kind: GrantedKind) -> Self {
        Self { service, kind }
    }

    /// The grant as the guard sees it: a wildcard needs the wildcard key, a sensitive exact key
    /// the sensitive key, and every other grant only the key of its service.
    #[must_use]
    pub fn of(grant: &PermissionGrant, sensitive: bool) -> Self {
        let kind = if grant.is_wildcard() {
            GrantedKind::Wildcard
        } else if sensitive {
            GrantedKind::Sensitive
        } else {
            GrantedKind::Plain
        };
        Self::new(grant.service().clone(), kind)
    }

    /// The service of the grant; a reserved key belongs to `iam`.
    #[must_use]
    pub const fn service(&self) -> &ServiceName {
        &self.service
    }

    /// What the grant needs besides the key of its service.
    #[must_use]
    pub const fn kind(&self) -> GrantedKind {
        self.kind
    }
}

/// The refusal of a change that would raise a privilege beyond the actor's own; the application
/// answers 403 and audits the attempt.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EscalationDenied {
    /// The actor does not hold the reserved key at global scope.
    #[error("Granting this needs {key}, held at global scope.")]
    Missing {
        /// The first reserved key the actor lacks.
        key: ReservedPermission,
    },
    /// The assignment names the actor as its subject.
    #[error("An actor cannot create, change or revoke its own assignment.")]
    OwnAssignment,
}

impl EscalationDenied {
    /// The machine-readable refusal code, recorded as the reason of the rejected audit record.
    pub const CODE: &'static str = "escalation.denied";
}

/// The rule for granting a key of service `s`.
///
/// It needs `iam:grant:s` or `iam:grant:*` at global scope, plus `iam:grant:sensitive` for a
/// sensitive key and `iam:grant:wildcard` for a wildcard.
#[derive(Debug, Clone, Copy)]
pub struct EscalationGuard;

impl EscalationGuard {
    /// The reserved keys that the grants need, each once, in the order of their first need.
    #[must_use]
    pub fn required(granted: &[GrantedKey]) -> Vec<ReservedPermission> {
        let mut seen = BTreeSet::new();
        let mut required = Vec::new();
        for key in granted {
            let needs = [
                Some(ReservedPermission::Grant(ServiceScope::Service(
                    key.service.clone(),
                ))),
                match key.kind {
                    GrantedKind::Plain => None,
                    GrantedKind::Sensitive => Some(ReservedPermission::GrantSensitive),
                    GrantedKind::Wildcard => Some(ReservedPermission::GrantWildcard),
                },
            ];
            for need in needs.into_iter().flatten() {
                if seen.insert(need.clone()) {
                    required.push(need);
                }
            }
        }
        required
    }

    /// Lets the grants through when the actor's policy holds every reserved key they need at
    /// global scope at `now`.
    ///
    /// # Errors
    ///
    /// [`EscalationDenied::Missing`] with the first key the actor lacks.
    pub fn check(
        policy: &SubjectPolicy,
        now: SystemTime,
        granted: &[GrantedKey],
    ) -> Result<(), EscalationDenied> {
        Self::required(granted)
            .into_iter()
            .find(|key| !policy.holds_reserved(key, now))
            .map_or(Ok(()), |key| Err(EscalationDenied::Missing { key }))
    }

    /// Refuses an assignment whose subject is the actor itself.
    ///
    /// # Errors
    ///
    /// [`EscalationDenied::OwnAssignment`] when `actor` and `subject` are the same subject.
    pub fn check_subject(actor: &SubjectRef, subject: &SubjectRef) -> Result<(), EscalationDenied> {
        if actor == subject {
            Err(EscalationDenied::OwnAssignment)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
