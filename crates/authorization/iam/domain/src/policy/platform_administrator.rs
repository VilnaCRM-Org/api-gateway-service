//! The system role `iam-platform-admin` that the bootstrap creates (FR-5).

use crate::role::RoleParts;
use crate::value_object::role_kind::RoleKind;

/// What the bootstrap seeds: the name of the administrator role and every key it grants.
#[derive(Debug, Clone, Copy)]
pub struct PlatformAdministrator;

impl PlatformAdministrator {
    /// The name of the system role.
    pub const ROLE_NAME: &'static str = "iam-platform-admin";

    /// The grants of the role as text: the wildcards over IAM's own operations and every reserved
    /// key.
    pub const GRANTS: [&'static str; 13] = [
        "rest:iam:*",
        "gql:iam:*",
        "iam:validate:*",
        "iam:grant:*",
        "iam:grant:sensitive",
        "iam:grant:wildcard",
        "iam:spec:*",
        "iam:audit:read",
        "iam:revoke:sessions",
        "iam:revoke:global",
        "iam:policy:resync",
        "iam:route:anonymous",
        "iam:route:*",
    ];

    /// Whether the role is the administrator role: a system role of that name.
    #[must_use]
    pub fn is_role(role: &RoleParts) -> bool {
        role.kind == RoleKind::System && role.name.as_str() == Self::ROLE_NAME
    }
}

#[cfg(test)]
mod tests;
