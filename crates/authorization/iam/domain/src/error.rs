//! Domain errors of the IAM context.

use crate::value_object::entity_version::EntityVersion;

/// A value that breaks an invariant of a shared identity, name, scope or version value object of IAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidIamValue {
    /// The policy version is negative.
    #[error("This value must be 0 or greater.")]
    PolicyVersionNegative,
    /// The policy digest is not exactly 16 bytes long.
    #[error("This value must contain exactly 16 bytes.")]
    PolicyDigestLength,
    /// The log epoch is negative.
    #[error("This value must be 0 or greater.")]
    LogEpochNegative,
    /// The relay epoch is negative.
    #[error("This value must be 0 or greater.")]
    RelayEpochNegative,
    /// The catalogue epoch is negative.
    #[error("This value must be 0 or greater.")]
    CatalogEpochNegative,
    /// An identifier is not a UUID.
    #[error("This value must be a valid UUID.")]
    Identifier,
    /// A service name is empty or longer than 63 characters.
    #[error("This value must contain between 1 and 63 characters.")]
    ServiceNameLength,
    /// A service name does not match `^[a-z][a-z0-9]*(-[a-z0-9]+)*$`.
    #[error("This value must be a lower-case service name such as user-service.")]
    ServiceNamePattern,
    /// A subject kind is neither `user` nor `service`.
    #[error("This value must be user or service.")]
    SubjectKind,
    /// The id of a user subject is not a UUID.
    #[error("This value must be a valid UUID.")]
    SubjectUserId,
    /// An entity version is below 1 or cannot be increased.
    #[error("This value must be between 1 and 9223372036854775807.")]
    EntityVersionRange,
    /// A request id is empty, too long or holds a character that is not visible ASCII.
    #[error("This value must contain between 1 and 128 visible ASCII characters.")]
    RequestIdFormat,
    /// An idempotency key is empty, too long or holds a character that is not visible ASCII.
    #[error("This value must contain between 1 and 255 visible ASCII characters.")]
    IdempotencyKeyFormat,
    /// A scope kind is neither `global` nor `project`.
    #[error("This value must be global or project.")]
    ScopeKind,
    /// A project scope has no project id.
    #[error("A project scope needs a project id.")]
    ScopeProjectMissing,
    /// A global scope has a project id.
    #[error("A global scope takes no project id.")]
    ScopeProjectUnexpected,
    /// A grant set holds more than 5,000 distinct grants.
    #[error("This collection must contain 5000 elements or fewer.")]
    GrantSetTooLarge,
    /// An actor reference is not `user:<uuid>`, `service:<name>` or `system:<component>`.
    #[error("This value must be user:<uuid>, service:<name> or system:<component>.")]
    ActorFormat,
    /// An audit action is not made of dotted lower-case words of at most 100 characters.
    #[error("This value must be dotted lower-case words of at most 100 characters.")]
    AuditActionFormat,
    /// An audit outcome is neither `committed` nor `rejected`.
    #[error("This value must be committed or rejected.")]
    AuditOutcome,
    /// An audit timestamp lies before 1970 or too far in the future for microseconds in 64 bits.
    #[error("This value must be a time between 1970-01-01 and 294247-01-10.")]
    AuditTimestamp,
    /// An audit target type is not a lower-case word of at most 50 characters.
    #[error("This value must be a lower-case word of at most 50 characters.")]
    AuditTargetType,
    /// An audit target id is empty, too long or holds a character that is not visible ASCII.
    #[error("This value must contain between 1 and 255 visible ASCII characters.")]
    AuditTargetId,
    /// An audit summary is empty, too long, holds a control character or a credential.
    #[error("This value must contain between 1 and 4096 printable characters and no credential.")]
    AuditSummaryFormat,
    /// An audit reason is not a lower-case code of at most 100 characters.
    #[error("This value must be a lower-case code of at most 100 characters.")]
    AuditReasonFormat,
    /// An audit hash is not exactly 32 bytes long.
    #[error("This value must contain exactly 32 bytes.")]
    AuditHashLength,
    /// An audit sequence number is out of range: negative for a chain head, below 1 for a record.
    #[error("This value is outside the range of audit sequence numbers.")]
    AuditSequence,
}

impl InvalidIamValue {
    /// The property that carries the invalid value.
    #[must_use]
    pub const fn property_path(self) -> &'static str {
        match self {
            Self::PolicyVersionNegative | Self::EntityVersionRange => "version",
            Self::PolicyDigestLength => "digest",
            Self::LogEpochNegative => "logEpoch",
            Self::RelayEpochNegative => "relayEpoch",
            Self::CatalogEpochNegative => "catalogEpoch",
            Self::Identifier => "id",
            Self::ServiceNameLength | Self::ServiceNamePattern => "service",
            Self::SubjectKind => "subject.kind",
            Self::SubjectUserId => "subject.id",
            Self::RequestIdFormat => "requestId",
            Self::IdempotencyKeyFormat => "idempotencyKey",
            Self::ScopeKind => "scope.kind",
            Self::ScopeProjectMissing | Self::ScopeProjectUnexpected => "scope.projectId",
            Self::GrantSetTooLarge => "permissions",
            Self::ActorFormat => "actor",
            Self::AuditActionFormat => "action",
            Self::AuditOutcome => "outcome",
            Self::AuditTimestamp => "occurredAt",
            Self::AuditTargetType => "targetType",
            Self::AuditTargetId => "targetId",
            Self::AuditSummaryFormat => "summary",
            Self::AuditReasonFormat => "reason",
            Self::AuditHashLength => "hash",
            Self::AuditSequence => "seq",
        }
    }

    /// The machine-readable violation code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PolicyDigestLength | Self::ServiceNameLength | Self::AuditHashLength => "length",
            Self::PolicyVersionNegative
            | Self::LogEpochNegative
            | Self::RelayEpochNegative
            | Self::CatalogEpochNegative
            | Self::EntityVersionRange
            | Self::AuditTimestamp
            | Self::AuditSequence => "range",
            Self::Identifier | Self::SubjectUserId => "uuid",
            Self::ServiceNamePattern => "pattern",
            Self::SubjectKind | Self::ScopeKind | Self::AuditOutcome => "choice",
            Self::RequestIdFormat
            | Self::IdempotencyKeyFormat
            | Self::ActorFormat
            | Self::AuditActionFormat
            | Self::AuditTargetType
            | Self::AuditTargetId
            | Self::AuditSummaryFormat
            | Self::AuditReasonFormat => "format",
            Self::ScopeProjectMissing => "required",
            Self::ScopeProjectUnexpected => "forbidden",
            Self::GrantSetTooLarge => "count",
        }
    }
}

/// A permission key or wildcard pattern that does not have one of the accepted forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidPermissionKey {
    /// The key does not start with `rest:`, `gql:` or `iam:`.
    #[error("This permission key must start with rest:, gql: or iam:.")]
    Kind,
    /// The service segment is not a valid service name.
    #[error("The service segment of this permission key is not a valid service name.")]
    Service,
    /// Nothing, or no separated operation, follows the service segment.
    #[error("This permission key has no operation after its service segment.")]
    Operation,
    /// The HTTP method of a REST key is unknown.
    #[error("This permission key names an unknown HTTP method.")]
    Method,
    /// The path template of a REST key is invalid.
    #[error("The path template of this permission key is invalid.")]
    Template,
    /// The `{Type}.{field}` coordinate of a GraphQL key is invalid.
    #[error("The GraphQL coordinate of this permission key is invalid.")]
    Coordinate,
    /// The `iam:` key is not one of the reserved keys.
    #[error("This reserved iam: permission key does not exist.")]
    Reserved,
    /// The text is not one of the four wildcard forms.
    #[error("This value is not one of the four wildcard forms.")]
    Wildcard,
}

impl InvalidPermissionKey {
    /// The property that carries the invalid key.
    pub const PROPERTY_PATH: &'static str = "key";

    /// The machine-readable violation code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Kind => "kind",
            Self::Service => "service",
            Self::Operation => "operation",
            Self::Method => "method",
            Self::Template => "template",
            Self::Coordinate => "coordinate",
            Self::Reserved => "reserved",
            Self::Wildcard => "wildcard",
        }
    }
}

/// A change names no version or a version that is not the current one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VersionConflict {
    /// The change names no expected version.
    #[error("The request must name the version it changes.")]
    Missing,
    /// The expected version differs from the current one.
    #[error(
        "The request names version {}, but the current version is {}.",
        expected.value(),
        current.value()
    )]
    Stale {
        /// The version the change expects.
        expected: EntityVersion,
        /// The version that is stored.
        current: EntityVersion,
    },
}

impl VersionConflict {
    /// The property that carries the conflicting version.
    pub const PROPERTY_PATH: &'static str = "version";

    /// The machine-readable conflict code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Stale { .. } => "stale",
        }
    }
}

#[cfg(test)]
mod tests;
