//! Bounded context `iam`, domain layer: aggregates, value objects, domain events, domain
//! errors and the ports (such as repository traits) that the infrastructure layer implements.
//!
//! This crate is framework-free. It depends on domain crates only: its own context and the shared
//! kernel, never another bounded context.

pub mod entity;
pub mod error;
mod micros;
pub mod policy;
pub mod port;
pub mod revocation;
pub mod role;
pub mod value_object;

pub use entity::change_receipt::ChangeReceipt;
pub use entity::event_envelope::{EventEnvelope, EventEnvelopeParts, IamDomainEvent};
pub use entity::iam_change::{IamChange, IamChangeParts};
pub use entity::idempotency_record::{IdempotencyRecord, IdempotencyRequest};
pub use entity::security_audit_event::{
    SecurityAuditEvent, SecurityAuditEventParts, StoredSecurityAuditEvent,
};
pub use error::{
    InvalidEventEnvelope, InvalidIamValue, InvalidPermissionKey, InvalidRole, RoleChangeRefused,
    VersionConflict,
};
pub use policy::token_lifetime_rule::{TokenLifetimeRule, TokenTimes};
pub use port::RepositoryError;
pub use port::access_token_verifier::AccessTokenVerifier;
pub use port::boot_clock::BootClock;
pub use port::change_receipt_repository::ChangeReceiptRepository;
pub use port::iam_unit_of_work::IamUnitOfWork;
pub use port::idempotency_repository::IdempotencyRepository;
pub use port::policy_epoch_repository::PolicyEpochRepository;
pub use port::revocation_repository::RevocationRepository;
pub use port::revocation_view::RevocationView;
pub use port::rng::Rng;
pub use port::role_repository::{RolePageQuery, RoleRepository};
pub use port::security_audit_log::SecurityAuditLog;
pub use port::token_memo::{TokenMemo, Verification};
pub use port::token_repository::TokenRepository;
pub use revocation::global_token_cutoff::GlobalTokenCutoff;
pub use revocation::inbound_event::{InboundEvent, InboundOutcome};
pub use revocation::revocation_rule::{RevocationRule, RevocationStatus};
pub use revocation::revocation_source::RevocationSource;
pub use revocation::session_revocation::SessionRevocation;
pub use revocation::user_token_cutoff::UserTokenCutoff;
pub use role::event::{RoleCreated, RoleDeleted, RolePermissionsChanged, RoleUpdated};
pub use role::{Role, RoleDescriptionChange, RoleFields, RoleParts, RolePatch, RoleStamp};
pub use value_object::access_token::{AccessToken, AccessTokenParts};
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
pub use value_object::change_statement::ChangeStatement;
pub use value_object::credential::Credential;
pub use value_object::credential_digest::CredentialDigest;
pub use value_object::decision_effect::DecisionEffect;
pub use value_object::entity_version::EntityVersion;
pub use value_object::event_data::{EventData, EventValue};
pub use value_object::event_type::EventType;
pub use value_object::gql_name::GqlName;
pub use value_object::http_method::HttpMethod;
pub use value_object::idempotency_key::IdempotencyKey;
pub use value_object::identifier::{
    ChangeId, DecisionId, PermissionId, ProjectId, RoleId, SecurityAuditEventId,
    SessionRevocationId, SpecId, UserRoleId,
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
pub use value_object::request_digest::RequestDigest;
pub use value_object::request_id::RequestId;
pub use value_object::reserved_permission::{ReservedPermission, ServiceScope};
pub use value_object::rest_template::RestTemplate;
pub use value_object::role_description::RoleDescription;
pub use value_object::role_kind::RoleKind;
pub use value_object::role_name::RoleName;
pub use value_object::scope_set::ScopeSet;
pub use value_object::service_name::ServiceName;
pub use value_object::session_id::SessionId;
pub use value_object::subject::{SubjectId, SubjectKind, SubjectRef};
pub use value_object::token_id::TokenId;
pub use value_object::token_identity::TokenIdentity;
pub use value_object::token_rejection::TokenRejection;
pub use value_object::wildcard_pattern::WildcardPattern;
