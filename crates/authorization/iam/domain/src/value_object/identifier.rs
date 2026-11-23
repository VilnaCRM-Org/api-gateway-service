//! UUID identifiers of the IAM records.

use shared_domain::Uuid;

use crate::error::InvalidIamValue;

/// Defines a UUID identifier type with the same constructors, accessor and text form.
macro_rules! uuid_identifier {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Uuid);

        impl $name {
            /// Wraps a UUID, for example one from the `UuidGenerator` port.
            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            /// Parses the text form of a UUID.
            ///
            /// # Errors
            ///
            /// Returns [`InvalidIamValue::Identifier`] when the text is not a UUID.
            pub fn parse(value: &str) -> Result<Self, InvalidIamValue> {
                Uuid::parse(value)
                    .map(Self)
                    .map_err(|_error| InvalidIamValue::Identifier)
            }

            /// The wrapped UUID.
            #[must_use]
            pub const fn as_uuid(&self) -> Uuid {
                self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

uuid_identifier! {
    /// The identifier of a role.
    RoleId
}

uuid_identifier! {
    /// The identifier of an assignment of a role to a subject.
    UserRoleId
}

uuid_identifier! {
    /// The identifier of a loaded GraphQL or `OpenAPI` specification.
    SpecId
}

uuid_identifier! {
    /// The identifier of a catalogue entry.
    PermissionId
}

uuid_identifier! {
    /// The identifier of one access decision (a UUID v7 from the `UuidGenerator` port).
    DecisionId
}

uuid_identifier! {
    /// The identifier of one administrative change.
    ChangeId
}

uuid_identifier! {
    /// The identifier of a project that scopes an assignment.
    ProjectId
}

uuid_identifier! {
    /// The identifier of one security audit record.
    SecurityAuditEventId
}

uuid_identifier! {
    /// The identifier of one session revocation, exposed by the management API.
    SessionRevocationId
}

uuid_identifier! {
    /// The identifier of an upstream.
    UpstreamId
}

uuid_identifier! {
    /// The identifier of a route.
    RouteId
}

uuid_identifier! {
    /// The identifier of a rate policy.
    RatePolicyId
}

#[cfg(test)]
mod tests;
