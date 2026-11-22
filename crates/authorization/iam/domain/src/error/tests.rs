use rstest::rstest;

use super::{InvalidEventEnvelope, InvalidIamValue, InvalidPermissionKey, VersionConflict};
use crate::value_object::entity_version::EntityVersion;

const NEGATIVE: &str = "This value must be 0 or greater.";
const DIGEST: &str = "This value must contain exactly 16 bytes.";

#[rstest]
#[case(InvalidIamValue::PolicyVersionNegative, "version", "range", NEGATIVE)]
#[case(InvalidIamValue::PolicyDigestLength, "digest", "length", DIGEST)]
#[case(InvalidIamValue::LogEpochNegative, "logEpoch", "range", NEGATIVE)]
#[case(InvalidIamValue::RelayEpochNegative, "relayEpoch", "range", NEGATIVE)]
#[case(
    InvalidIamValue::CatalogEpochNegative,
    "catalogEpoch",
    "range",
    NEGATIVE
)]
#[case(
    InvalidIamValue::Identifier,
    "id",
    "uuid",
    "This value must be a valid UUID."
)]
#[case(
    InvalidIamValue::ServiceNameLength,
    "service",
    "length",
    "This value must contain between 1 and 63 characters."
)]
#[case(
    InvalidIamValue::ServiceNamePattern,
    "service",
    "pattern",
    "This value must be a lower-case service name such as user-service."
)]
#[case(
    InvalidIamValue::SubjectKind,
    "subject.kind",
    "choice",
    "This value must be user or service."
)]
#[case(
    InvalidIamValue::SubjectUserId,
    "subject.id",
    "uuid",
    "This value must be a valid UUID."
)]
#[case(
    InvalidIamValue::EntityVersionRange,
    "version",
    "range",
    "This value must be between 1 and 9223372036854775807."
)]
#[case(
    InvalidIamValue::RequestIdFormat,
    "requestId",
    "format",
    "This value must contain between 1 and 128 visible ASCII characters."
)]
#[case(
    InvalidIamValue::IdempotencyKeyFormat,
    "idempotencyKey",
    "format",
    "This value must contain between 1 and 255 visible ASCII characters."
)]
#[case(
    InvalidIamValue::ScopeKind,
    "scope.kind",
    "choice",
    "This value must be global or project."
)]
#[case(
    InvalidIamValue::ScopeProjectMissing,
    "scope.projectId",
    "required",
    "A project scope needs a project id."
)]
#[case(
    InvalidIamValue::ScopeProjectUnexpected,
    "scope.projectId",
    "forbidden",
    "A global scope takes no project id."
)]
#[case(
    InvalidIamValue::GrantSetTooLarge,
    "permissions",
    "count",
    "This collection must contain 5000 elements or fewer."
)]
#[case(
    InvalidIamValue::ActorFormat,
    "actor",
    "format",
    "This value must be user:<uuid>, service:<name> or system:<component>."
)]
#[case(
    InvalidIamValue::AuditActionFormat,
    "action",
    "format",
    "This value must be dotted lower-case words of at most 100 characters."
)]
#[case(
    InvalidIamValue::AuditOutcome,
    "outcome",
    "choice",
    "This value must be committed or rejected."
)]
#[case(
    InvalidIamValue::AuditTimestamp,
    "occurredAt",
    "range",
    "This value must be a time between 1970-01-01 and 294247-01-10."
)]
#[case(
    InvalidIamValue::AuditTargetType,
    "targetType",
    "format",
    "This value must be a lower-case word of at most 50 characters."
)]
#[case(
    InvalidIamValue::AuditTargetId,
    "targetId",
    "format",
    "This value must contain between 1 and 255 visible ASCII characters."
)]
#[case(
    InvalidIamValue::AuditSummaryFormat,
    "summary",
    "format",
    "This value must contain between 1 and 4096 printable characters and no credential."
)]
#[case(
    InvalidIamValue::AuditReasonFormat,
    "reason",
    "format",
    "This value must be a lower-case code of at most 100 characters."
)]
#[case(
    InvalidIamValue::AuditHashLength,
    "hash",
    "length",
    "This value must contain exactly 32 bytes."
)]
#[case(
    InvalidIamValue::AuditSequence,
    "seq",
    "range",
    "This value is outside the range of audit sequence numbers."
)]
#[case(
    InvalidIamValue::RequestDigestLength,
    "requestDigest",
    "length",
    "This value must contain exactly 32 bytes."
)]
#[case(
    InvalidIamValue::ChangeAuditOutcome,
    "audit.outcome",
    "choice",
    "A committed change needs an audit record with outcome committed."
)]
fn exposes_the_property_path_the_code_and_the_message(
    #[case] error: InvalidIamValue,
    #[case] property_path: &str,
    #[case] code: &str,
    #[case] message: &str,
) {
    assert_eq!(error.property_path(), property_path);
    assert_eq!(error.code(), code);
    assert_eq!(error.to_string(), message);
}

#[rstest]
#[case(
    InvalidEventEnvelope::IdVersion,
    "id",
    "uuid",
    "This value must be a version 7 UUID."
)]
#[case(
    InvalidEventEnvelope::EventType,
    "type",
    "format",
    "This value must be dotted lower-case words of the form iam.<aggregate>.<verb>."
)]
#[case(
    InvalidEventEnvelope::Timestamp,
    "occurredAt",
    "range",
    "This value must be a time between 1970-01-01 and 9999-12-31."
)]
#[case(
    InvalidEventEnvelope::FieldName,
    "data",
    "format",
    "This field name must be a lower camel-case word of at most 64 characters."
)]
#[case(
    InvalidEventEnvelope::FieldDuplicate,
    "data",
    "duplicate",
    "This field name is already used in the object."
)]
#[case(
    InvalidEventEnvelope::FieldReserved,
    "data",
    "reserved",
    "This field name is reserved for the common fields of the envelope."
)]
#[case(
    InvalidEventEnvelope::FieldForbidden,
    "data",
    "forbidden",
    "This field name names a credential or a specification body."
)]
#[case(
    InvalidEventEnvelope::Credential,
    "data",
    "forbidden",
    "This value must not hold a credential."
)]
#[case(
    InvalidEventEnvelope::ControlCharacter,
    "data",
    "format",
    "This value must not hold a control character."
)]
#[case(
    InvalidEventEnvelope::TooLarge,
    "envelope",
    "length",
    "The encoded event must be at most 65536 bytes."
)]
fn an_invalid_envelope_exposes_the_property_path_the_code_and_the_message(
    #[case] error: InvalidEventEnvelope,
    #[case] property_path: &str,
    #[case] code: &str,
    #[case] message: &str,
) {
    assert_eq!(error.property_path(), property_path);
    assert_eq!(error.code(), code);
    assert_eq!(error.to_string(), message);
}

#[rstest]
#[case(
    InvalidPermissionKey::Kind,
    "kind",
    "This permission key must start with rest:, gql: or iam:."
)]
#[case(
    InvalidPermissionKey::Service,
    "service",
    "The service segment of this permission key is not a valid service name."
)]
#[case(
    InvalidPermissionKey::Operation,
    "operation",
    "This permission key has no operation after its service segment."
)]
#[case(
    InvalidPermissionKey::Method,
    "method",
    "This permission key names an unknown HTTP method."
)]
#[case(
    InvalidPermissionKey::Template,
    "template",
    "The path template of this permission key is invalid."
)]
#[case(
    InvalidPermissionKey::Coordinate,
    "coordinate",
    "The GraphQL coordinate of this permission key is invalid."
)]
#[case(
    InvalidPermissionKey::Reserved,
    "reserved",
    "This reserved iam: permission key does not exist."
)]
#[case(
    InvalidPermissionKey::Wildcard,
    "wildcard",
    "This value is not one of the four wildcard forms."
)]
fn a_malformed_key_has_the_key_path_its_code_and_its_message(
    #[case] error: InvalidPermissionKey,
    #[case] code: &str,
    #[case] message: &str,
) {
    assert_eq!(InvalidPermissionKey::PROPERTY_PATH, "key");
    assert_eq!(error.code(), code);
    assert_eq!(error.to_string(), message);
}

#[test]
fn a_missing_and_a_stale_version_are_told_apart() {
    let expected = EntityVersion::new(2).unwrap();
    let current = EntityVersion::new(3).unwrap();
    let stale = VersionConflict::Stale { expected, current };

    assert_ne!(VersionConflict::Missing, stale);
    assert_eq!(VersionConflict::PROPERTY_PATH, "version");
    assert_eq!(VersionConflict::Missing.code(), "missing");
    assert_eq!(
        VersionConflict::Missing.to_string(),
        "The request must name the version it changes."
    );
    assert_eq!(stale.code(), "stale");
    assert_eq!(
        stale.to_string(),
        "The request names version 2, but the current version is 3."
    );
}
