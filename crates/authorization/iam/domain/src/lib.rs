//! Bounded context `iam`, domain layer: aggregates, value objects, domain events, domain
//! errors and the ports (such as repository traits) that the infrastructure layer implements.
//!
//! This crate is framework-free. It depends on domain crates only: its own context and the shared
//! kernel, never another bounded context.

pub mod entity;
pub mod error;
pub mod port;
pub mod value_object;

pub use entity::security_audit_event::{
    SecurityAuditEvent, SecurityAuditEventParts, StoredSecurityAuditEvent,
};
pub use error::{InvalidIamValue, InvalidPermissionKey, VersionConflict};
pub use port::RepositoryError;
pub use port::boot_clock::BootClock;
pub use port::policy_epoch_repository::PolicyEpochRepository;
pub use port::rng::Rng;
pub use port::security_audit_log::SecurityAuditLog;
pub use value_object::actor_ref::{ActorRef, SystemComponent};
pub use value_object::assignment_scope::AssignmentScope;
pub use value_object::audit_action::AuditAction;
pub use value_object::audit_chain_head::AuditChainHead;
pub use value_object::audit_hash::AuditHash;
pub use value_object::audit_outcome::AuditOutcome;
pub use value_object::audit_reason::AuditReason;
pub use value_object::audit_summary::AuditSummary;
pub use value_object::audit_target::AuditTarget;
pub use value_object::boot_instant::BootInstant;
pub use value_object::entity_version::EntityVersion;
pub use value_object::gql_name::GqlName;
pub use value_object::http_method::HttpMethod;
pub use value_object::idempotency_key::IdempotencyKey;
pub use value_object::identifier::{
    ChangeId, DecisionId, PermissionId, ProjectId, RoleId, SecurityAuditEventId, SpecId, UserRoleId,
};
pub use value_object::log_epoch::LogEpoch;
pub use value_object::permission_flags::PermissionFlags;
pub use value_object::permission_grant::PermissionGrant;
pub use value_object::permission_grant_set::PermissionGrantSet;
pub use value_object::permission_key::{GqlCoordinate, PermissionKey, PermissionKeyKind};
pub use value_object::policy_digest_value::PolicyDigestValue;
pub use value_object::policy_epoch::PolicyEpoch;
pub use value_object::policy_version::PolicyVersion;
pub use value_object::relay_epoch::RelayEpoch;
pub use value_object::request_id::RequestId;
pub use value_object::reserved_permission::{ReservedPermission, ServiceScope};
pub use value_object::rest_template::RestTemplate;
pub use value_object::scope_set::ScopeSet;
pub use value_object::service_name::ServiceName;
pub use value_object::subject::{SubjectId, SubjectKind, SubjectRef};
pub use value_object::wildcard_pattern::WildcardPattern;
