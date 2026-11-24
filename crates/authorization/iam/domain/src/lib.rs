//! Bounded context `iam`, domain layer: aggregates, value objects, domain events, domain
//! errors and the ports (such as repository traits) that the infrastructure layer implements.
//!
//! This crate is framework-free. It depends on domain crates only: its own context and the shared
//! kernel, never another bounded context.

pub mod audit_anchor;
pub mod bulk_operation;
pub mod catalogue_event;
pub mod catalogue_statement;
pub mod derived_check;
pub mod endpoint;
pub mod entity;
pub mod error;
pub mod freshness;
pub mod gateway_seed;
pub mod gateway_statement;
pub mod graphql_permission;
pub mod graphql_spec;
pub mod kafka_topic;
pub mod maintenance;
mod micros;
pub mod openapi_spec;
pub mod policy;
pub mod port;
pub mod rate_limit;
pub mod rate_policy;
pub mod rejected_attempt;
pub mod rest_permission;
pub mod resync;
pub mod revocation;
pub mod role;
pub mod route;
pub mod security_audit_search;
pub mod snapshot;
pub mod state;
pub mod upstream;
pub mod user_role;
pub mod value_object;

pub use audit_anchor::{AnchorStamp, SecurityAuditAnchored};
pub use bulk_operation::chunker::{
    BulkChange, BulkChunk, BulkChunker, BulkPacing, ChangeDirection, InvalidBulkChunking,
};
pub use bulk_operation::event::BulkOperationCompleted;
pub use bulk_operation::statement::BulkProgressStatement;
pub use bulk_operation::{
    BulkKind, BulkOperation, BulkOperationParts, BulkOperationRefused, BulkStamp, BulkStatus,
    InvalidBulkOperation,
};
pub use catalogue_event::{GraphQlPermissionsCreated, PermissionsOrphaned, RestPermissionsCreated};
pub use catalogue_statement::{
    CatalogueStatement, CatalogueStatementParts, EntryFlags, EntryInsert, SpecTransition,
};
pub use derived_check::{CHECK_GROUPS, DerivedMismatch, DerivedStateAudit, in_group};
pub use endpoint::selector::{Candidate, DEFAULT_SPILL_THRESHOLD, EndpointSelector};
pub use endpoint::zone::{InvalidZone, Zone};
pub use endpoint::{Condition, EndpointConditions, EndpointParts, UpstreamEndpoint};
pub use entity::change_receipt::ChangeReceipt;
pub use entity::event_envelope::{EventEnvelope, EventEnvelopeParts, IamDomainEvent};
pub use entity::iam_change::{IamChange, IamChangeParts};
pub use entity::idempotency_record::{IdempotencyRecord, IdempotencyRequest};
pub use entity::security_audit_event::{
    SecurityAuditEvent, SecurityAuditEventParts, StoredSecurityAuditEvent,
};
pub use error::{
    ConfigChangeRefused, InvalidRatePolicy, InvalidRoute, InvalidUpstream, ReferencedByRoute,
    RouteConflict, UpstreamChangeRefused,
};
pub use error::{
    InvalidAccessCheck, InvalidEventEnvelope, InvalidIamValue, InvalidPermissionKey, InvalidRole,
    InvalidUserRole, RoleChangeRefused, UserRoleChangeRefused, VersionConflict,
};
pub use error::{InvalidCatalogueEntry, InvalidStateRecord, RenameRefused};
pub use error::{InvalidSpec, SpecPosition, SpecTransitionRefused};
pub use freshness::probe_error::ProbeError;
pub use freshness::rule::{Freshness, FreshnessRule, StaleCause};
pub use gateway_seed::IamGatewaySeed;
pub use gateway_statement::{GatewayPrecondition, GatewayStatement};
pub use graphql_permission::{GraphQlPermission, GraphQlPermissionParts};
pub use graphql_spec::event::{GraphQlSpecLoaded, GraphQlSpecRetired};
pub use graphql_spec::statement::GraphQlSpecStatement;
pub use graphql_spec::{
    GraphQlSpec, GraphQlSpecContent, GraphQlSpecParts, SpecActivation, SpecStamp,
};
pub use kafka_topic::{
    AllowEveryoneEvidence, CONTROL_PRINCIPAL, CheckSource, ConfigGates, ConfigurationRules,
    ConfigurationVerdict, TopicObservation, Violation,
};
pub use maintenance::{
    ExpiredOrphanedGrant, INBOUND_EVENT_RETENTION, MAX_PURGED_GRANTS_PER_RUN, PurgedRecords,
    RECORD_RETENTION, RetentionCutoffs,
};
pub use openapi_spec::event::{OpenApiSpecLoaded, OpenApiSpecRetired};
pub use openapi_spec::statement::OpenApiSpecStatement;
pub use openapi_spec::{OpenApiSpec, OpenApiSpecContent, OpenApiSpecParts};
pub use policy::anonymous_route_guard::{AnonymousRouteGuard, AnonymousRouteRefused};
pub use policy::caller_token_rule::CallerTokenRule;
pub use policy::catalogue_activation::{
    CatalogueActivation, FlagChange, GrantRecord, KeyRename, OrphanedGrant,
};
pub use policy::change_guard::GuardCheck;
pub use policy::compiled_role_set::{CompiledRoleSet, GrantStatus};
pub use policy::decision_policy::{
    DecisionPolicy, DecisionRequest, RequiredKey, RoleAssignment, RoleSets,
};
pub use policy::effective_permission_composer::{
    EffectivePermission, EffectivePermissionComposer, EffectivePermissionFilter, UserRolePermission,
};
pub use policy::escalation_guard::{EscalationDenied, EscalationGuard, GrantedKey, GrantedKind};
pub use policy::last_administrator_guard::{LastAdministratorGuard, LastAdministratorRefused};
pub use policy::orphan_policy::{OrphanPolicy, RenameMap};
pub use policy::path_normalizer::{MalformedPath, PathNormalizer};
pub use policy::permission_catalogue::PermissionCatalogue;
pub use policy::platform_administrator::PlatformAdministrator;
pub use policy::rest_operation_matcher::{RestOperationMatcher, UnknownOperation};
pub use policy::rest_spec_diff::{
    RemovedRestGrant, RestFlagDowngrade, RestSpecDiff, RestWildcardGain,
};
pub use policy::route_conflict_guard::RouteConflictGuard;
pub use policy::route_revocation_rule::{RouteChangeClass, RouteRevocationRule};
pub use policy::route_scope_guard::{RouteScopeGuard, RouteScopeRefused};
pub use policy::route_set_diff::{ChangedRoute, RouteSetDiff};
pub use policy::route_set_version::RouteSetVersion;
pub use policy::service_catalog::ServiceCatalog;
pub use policy::spec_diff::{FlagDowngrade, RemovedGrant, RoleGrants, SpecDiff, WildcardGain};
pub use policy::spec_scope_guard::{SpecScopeDenied, SpecScopeGuard};
pub use policy::subject_policy::SubjectPolicy;
pub use policy::token_lifetime_rule::{TokenLifetimeRule, TokenTimes};
pub use policy::wildcard_matcher::WildcardMatcher;
pub use port::RepositoryError;
pub use port::access_token_verifier::AccessTokenVerifier;
pub use port::anti_entropy_store::{AntiEntropyStore, PublishedRecord, StoredHead, WrittenKey};
pub use port::boot_clock::BootClock;
pub use port::bulk_chunk_committer::{BulkChunkCommitter, ChunkCommitError, CommittedChunk};
pub use port::bulk_operation_repository::BulkOperationRepository;
pub use port::bulk_role_target_store::BulkRoleTargetStore;
pub use port::change_receipt_repository::ChangeReceiptRepository;
pub use port::endpoint_watch::{
    EndpointListing, EndpointSlice, EndpointWatch, EndpointWatchError, SliceChange, WatchBatch,
    WatchTarget,
};
pub use port::expired_revocation_store::ExpiredRevocationStore;
pub use port::graphql_document_analyzer::GraphQlDocumentAnalyzer;
pub use port::graphql_permission_repository::GraphQlPermissionRepository;
pub use port::graphql_schema_parser::GraphQlSchemaParser;
pub use port::graphql_spec_repository::{GraphQlSpecPageQuery, GraphQlSpecRepository};
pub use port::iam_unit_of_work::IamUnitOfWork;
pub use port::idempotency_repository::IdempotencyRepository;
pub use port::kafka_topic_inspector::{KafkaInspectionError, KafkaTopicInspector};
pub use port::local_rate_limiter::LocalRateLimiter;
pub use port::maintenance_store::MaintenanceStore;
pub use port::openapi_document_parser::OpenApiDocumentParser;
pub use port::openapi_spec_repository::{OpenApiSpecPageQuery, OpenApiSpecRepository};
pub use port::outbox_store::{OutboxKind, OutboxRow, OutboxStore, PublishedRow, RelayTakeover};
pub use port::peer_freshness_client::PeerFreshnessClient;
pub use port::permission_page_query::PermissionPageQuery;
pub use port::policy_bootstrap_log::{FramedRecord, PolicyBootstrapLog};
pub use port::policy_digest::PolicyDigest;
pub use port::policy_epoch_repository::PolicyEpochRepository;
pub use port::policy_log_probe::PolicyLogProbe;
pub use port::policy_log_producer::{
    LOG_SCHEMA, PolicyLogError, PolicyLogProducer, PolicyLogRecord, STATE_PARTITION,
};
pub use port::policy_log_tail::{PolicyLogTail, PolicyLogTailError, TAIL_READ_LIMIT, TailRecord};
pub use port::policy_read_repository::PolicyReadRepository;
pub use port::policy_state_inventory::PolicyStateInventory;
pub use port::policy_tail_log::{PolicyTailLog, TailBatch, TimedRecord};
pub use port::policy_view::PolicyView;
pub use port::propagation_store::PropagationStore;
pub use port::rate_limit_store::{RateLimitStore, RateLimitStoreError};
pub use port::rate_policy_repository::{RatePolicyPageQuery, RatePolicyRepository};
pub use port::rejected_attempt_log::RejectedAttemptLog;
pub use port::request_digester::RequestDigester;
pub use port::rest_permission_repository::RestPermissionRepository;
pub use port::revocation_repository::RevocationRepository;
pub use port::revocation_view::RevocationView;
pub use port::rng::Rng;
pub use port::role_repository::{RoleGrant, RolePageQuery, RoleRepository};
pub use port::route_repository::{RoutePageQuery, RouteRepository};
pub use port::route_table_compiler::{RouteMatcher, RouteTableCompiler};
pub use port::security_audit_log::SecurityAuditLog;
pub use port::singleton_leadership::{
    LeaderBatch, Leadership, SingletonLeadership, SingletonTask, TOPIC_AHEAD_STATE, TopicAheadState,
};
pub use port::startup_lock::{
    ADMINISTRATORS_LOCK, BOOTSTRAP_LOCK, LockGuard, OWN_SPECIFICATIONS_LOCK, StartupLock,
};
pub use port::state_record_codec::StateRecordCodec;
pub use port::task_state_repository::{TaskState, TaskStateRepository};
pub use port::token_lifetime_floor::TokenLifetimeFloor;
pub use port::token_memo::{TokenMemo, Verification};
pub use port::token_repository::TokenRepository;
pub use port::upstream_repository::{UpstreamPageQuery, UpstreamRepository};
pub use port::user_role_repository::{UserRolePageQuery, UserRoleRepository};
pub use rate_limit::decision::RateDecision;
pub use rate_limit::key::{InvalidRateKey, RateKey, RateKeyParts};
pub use rate_limit::rule::{RateDecisionRule, RateOutcome};
pub use rate_policy::event::{RatePolicyCreated, RatePolicyDeleted, RatePolicyUpdated};
pub use rate_policy::fields::{RateFallback, RateKeyKind, RatePolicyDraft, RatePolicyFields};
pub use rate_policy::statement::RatePolicyStatement;
pub use rate_policy::{RatePolicy, RatePolicyParts, RatePolicyStamp};
pub use rejected_attempt::{
    AttemptSummary, RejectedAttempt, RejectedAttemptBuffer, SUMMARY_WINDOW,
};
pub use rest_permission::{RestPermission, RestPermissionParts};
pub use resync::{EpochChange, InventoryEntry, PolicyResynced, Republication, ResyncStart};
pub use revocation::event::{GlobalTokensCutOff, SessionRevoked, UserTokensCutOff};
pub use revocation::expired_revocation::{ExpiredRevocation, MAX_TOMBSTONES_PER_RUN};
pub use revocation::global_token_cutoff::GlobalTokenCutoff;
pub use revocation::inbound_event::{InboundEvent, InboundOutcome};
pub use revocation::prune_policy::{CUTOFF_MARGIN, PRUNE_MARGIN, PrunePolicy, SKEW_ALLOWANCE};
pub use revocation::revocation_rule::{RevocationRule, RevocationStatus};
pub use revocation::revocation_source::RevocationSource;
pub use revocation::session_revocation::SessionRevocation;
pub use revocation::session_revocation_search::SessionRevocationSearch;
pub use revocation::statement::RevocationStatement;
pub use revocation::user_token_cutoff::UserTokenCutoff;
pub use role::event::{RoleCreated, RoleDeleted, RolePermissionsChanged, RoleUpdated};
pub use role::statement::RoleStatement;
pub use role::{Role, RoleDescriptionChange, RoleFields, RoleParts, RolePatch, RoleStamp};
pub use route::cors::{CorsDraft, CorsPolicy};
pub use route::event::{RouteConfigurationApplied, RouteCreated, RouteDeleted, RouteUpdated};
pub use route::fields::{RouteDraft, RouteFields};
pub use route::settings::{
    BodyLimit, EnforcementMode, RetryPolicy, RouteFlag, RouteFlags, RouteTimeouts,
};
pub use route::statement::RouteStatement;
pub use route::{Route, RouteParts, RouteStamp};
pub use security_audit_search::{SecurityAuditFilter, SecurityAuditSearch};
pub use snapshot::assembly::{Completeness, Offer, VersionAssembly, VersionedRecord};
pub use snapshot::read::{FreshnessProof, PolicySnapshot};
pub use snapshot::ring::{DIGEST_RING_CAPACITY, DigestRing};
pub use snapshot::rules::{ApplyPosition, ApplyRules, FenceVerdict, RecordVerdict};
pub use state::batch::{StateBatch, StateChange, StateRow};
pub use state::key::{CATALOGUE_CHUNK_VERSION, ChunkId, StateKey};
pub use state::layout::{CatalogueLayout, MAX_CHUNK_BYTES};
pub use state::model::{
    AssignmentState, CatalogueChunk, CatalogueEntryState, CatalogueManifest, GlobalRevocationState,
    GrantState, PolicyHead, PolicyState, RatePolicyState, RoleState, RouteState,
    SessionRevocationState, StateRecord, SubjectState, UpstreamState, UserRevocationState,
};
pub use state::shadow::{ShadowState, ShadowVerdict};
pub use upstream::event::{UpstreamCreated, UpstreamDeleted, UpstreamUpdated};
pub use upstream::settings::{
    UpstreamFields, UpstreamProtocol, UpstreamSettings, UpstreamSettingsDraft,
};
pub use upstream::statement::UpstreamStatement;
pub use upstream::{Upstream, UpstreamParts, UpstreamStamp};
pub use user_role::event::{
    AssignedRole, PrivilegedRoleAssigned, UserRoleAssigned, UserRoleRevoked, UserRoleUpdated,
};
pub use user_role::statement::UserRoleStatement;
pub use user_role::{
    PrivilegedGrants, RevocationCause, UserRole, UserRoleAssignment, UserRoleParts, UserRoleStamp,
};
pub use value_object::access_check::{
    AccessCheck, AccessTarget, GraphQlTarget, PermissionsTarget, RestTarget,
};
pub use value_object::access_token::{AccessToken, AccessTokenParts};
pub use value_object::actor_ref::{ActorRef, SystemComponent};
pub use value_object::analyzed_document::AnalyzedDocument;
pub use value_object::assignment_expiry::AssignmentExpiry;
pub use value_object::assignment_scope::AssignmentScope;
pub use value_object::audit_action::AuditAction;
pub use value_object::audit_chain_head::AuditChainHead;
pub use value_object::audit_hash::AuditHash;
pub use value_object::audit_outcome::AuditOutcome;
pub use value_object::audit_reason::AuditReason;
pub use value_object::audit_summary::AuditSummary;
pub use value_object::audit_target::AuditTarget;
pub use value_object::boot_instant::BootInstant;
pub use value_object::canonical_path::CanonicalPath;
pub use value_object::change_statement::ChangeStatement;
pub use value_object::content_hash::ContentHash;
pub use value_object::coordinate_set::CoordinateSet;
pub use value_object::credential::Credential;
pub use value_object::credential_digest::CredentialDigest;
pub use value_object::decision::Decision;
pub use value_object::decision_effect::DecisionEffect;
pub use value_object::decision_outcome::{DecisionOutcome, DecisionVerdict};
pub use value_object::decision_reason::DecisionReason;
pub use value_object::document_key::DocumentKey;
pub use value_object::document_limits::DocumentLimits;
pub use value_object::document_refusal::{DocumentRefusal, LimitKind};
pub use value_object::entity_version::EntityVersion;
pub use value_object::event_data::{EventData, EventValue};
pub use value_object::event_type::EventType;
pub use value_object::gql_name::GqlName;
pub use value_object::graphql_coordinate::GraphQlCoordinate;
pub use value_object::graphql_type_graph::{GraphQlField, GraphQlTypeGraph};
pub use value_object::http_method::HttpMethod;
pub use value_object::idempotency_key::IdempotencyKey;
pub use value_object::identifier::{
    BulkOperationId, ChangeId, DecisionId, PermissionId, ProjectId, RatePolicyId, RoleId, RouteId,
    SecurityAuditEventId, SessionRevocationId, SpecId, UpstreamId, UserRoleId,
};
pub use value_object::log_epoch::LogEpoch;
pub use value_object::normalized_path::NormalizedPath;
pub use value_object::path_pattern::{PathPattern, PathSegment};
pub use value_object::path_template::PathTemplate;
pub use value_object::permission_flags::PermissionFlags;
pub use value_object::permission_grant::PermissionGrant;
pub use value_object::permission_grant_set::PermissionGrantSet;
pub use value_object::permission_key::{GqlCoordinate, PermissionKey, PermissionKeyKind};
pub use value_object::policy_digest_value::PolicyDigestValue;
pub use value_object::policy_epoch::PolicyEpoch;
pub use value_object::policy_version::PolicyVersion;
pub use value_object::propagation_outcome::PropagationOutcome;
pub use value_object::relay_epoch::RelayEpoch;
pub use value_object::request_digest::RequestDigest;
pub use value_object::request_id::RequestId;
pub use value_object::reserved_permission::{ReservedPermission, ServiceScope};
pub use value_object::rest_operation_set::{
    RestOperation, RestOperationDetails, RestOperationKey, RestOperationSet,
};
pub use value_object::rest_template::RestTemplate;
pub use value_object::role_description::RoleDescription;
pub use value_object::role_kind::RoleKind;
pub use value_object::role_name::RoleName;
pub use value_object::route_host::RouteHost;
pub use value_object::scope_set::ScopeSet;
pub use value_object::service_name::ServiceName;
pub use value_object::session_id::SessionId;
pub use value_object::spec_status::SpecStatus;
pub use value_object::subject::{SubjectId, SubjectKind, SubjectRef};
pub use value_object::token_id::TokenId;
pub use value_object::token_identity::TokenIdentity;
pub use value_object::token_rejection::TokenRejection;
pub use value_object::upstream_name::UpstreamName;
pub use value_object::wildcard_pattern::WildcardPattern;
pub use value_object::write_mode::WriteMode;
