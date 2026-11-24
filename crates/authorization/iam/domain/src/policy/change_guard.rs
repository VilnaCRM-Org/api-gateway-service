//! `GuardCheck`: the administrative-rights check that a change asks the unit of work to run
//! against the stored policy before it commits (FR-24, FR-25, FR-30, FR-34).

use crate::value_object::identifier::RoleId;
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::service_name::ServiceName;
use crate::value_object::subject::SubjectRef;

/// What a change needs its actor to be allowed to do. The actor is the actor of the change's audit
/// record; an IAM component acts without a check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardCheck {
    /// Grant these grants to a role: `EscalationGuard` over the grants the change adds.
    Grants(Vec<PermissionGrant>),
    /// Create, change or revoke the assignment of `role_id` to `subject`: `EscalationGuard` over
    /// every grant the role holds, and never on an assignment whose subject is the actor.
    Assignment {
        /// Who holds or would hold the role.
        subject: SubjectRef,
        /// The assigned role.
        role_id: RoleId,
    },
    /// Load, activate or retire a specification of `service`: `SpecScopeGuard`.
    Spec {
        /// The service of the specification.
        service: ServiceName,
        /// Whether the change confirms a flag downgrade, which also needs `iam:grant:sensitive`.
        flag_downgrade: bool,
    },
    /// Create, change or delete an upstream or a route of these catalogue services:
    /// `RouteScopeGuard`, which needs `iam:route:{service}` or `iam:route:*` for each of them.
    RouteScope {
        /// The catalogue services of the entry before and after the change, each once.
        services: Vec<ServiceName>,
    },
}
