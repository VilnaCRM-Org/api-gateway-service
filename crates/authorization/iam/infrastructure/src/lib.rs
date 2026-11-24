//! Bounded context `iam`, infrastructure layer: the adapters that implement the ports of the
//! domain layer, such as persistence, cache and messaging.
//!
//! This crate depends on the domain layer of its own context and of the shared kernel, never on the
//! application layer. SQL lives here and nowhere else.

pub mod bucket_local_rate_limiter;
pub mod buffered_rejected_attempt_log;
pub mod clock;
pub mod kafka;
pub mod kubernetes;
pub mod persistence;
pub mod policy_snapshot;
pub mod policy_state;
pub mod request_digest;
pub mod rng;
pub mod token;

pub use bucket_local_rate_limiter::BucketLocalRateLimiter;
pub use buffered_rejected_attempt_log::BufferedRejectedAttemptLog;
pub use clock::LinuxBootClock;
pub use kafka::{
    BOOTSTRAP_PRINCIPAL, KafkaSecret, KafkaSecurity, KafkaSettings, KrafkaPolicyLogProducer,
    KrafkaPolicyLogTail, KrafkaTopicInspector, RelayMode, SaslMechanism,
};
pub use kubernetes::{
    KubernetesEndpointWatch, KubernetesSettings, KubernetesSetupError, StaticEndpointWatch,
    StaticEndpointsError,
};
pub use persistence::PgPolicyEpochRepository;
pub use persistence::advisory_lock_leadership::AdvisoryLockLeadership;
pub use persistence::anti_entropy_store::PgAntiEntropyStore;
pub use persistence::change_receipt::PgChangeReceiptRepository;
pub use persistence::graphql_permission::PgGraphQlPermissionRepository;
pub use persistence::graphql_spec::PgGraphQlSpecRepository;
pub use persistence::idempotency::PgIdempotencyRepository;
pub use persistence::maintenance_store::PgMaintenanceStore;
pub use persistence::openapi_spec::PgOpenApiSpecRepository;
pub use persistence::outbox_listener::PgOutboxListener;
pub use persistence::outbox_store::PgOutboxStore;
pub use persistence::policy_read::{PgPolicyReadRepository, PolicyReadHook};
pub use persistence::propagation_store::PgPropagationStore;
pub use persistence::rate_policy::PgRatePolicyRepository;
pub use persistence::rest_permission::PgRestPermissionRepository;
pub use persistence::revocation::PgRevocationRepository;
pub use persistence::revocation_view::PgRevocationView;
pub use persistence::role::PgRoleRepository;
pub use persistence::route::PgRouteRepository;
pub use persistence::security_audit_log::PgSecurityAuditLog;
pub use persistence::startup_lock::PgStartupLock;
pub use persistence::task_state::PgTaskStateRepository;
pub use persistence::unit_of_work::PgIamUnitOfWork;
pub use persistence::upstream::PgUpstreamRepository;
pub use persistence::user_role::PgUserRoleRepository;
pub use policy_snapshot::{
    ArcSwapPolicySnapshot, MatchitRouteTableCompiler, PUBLISH_INTERVAL, PolicySnapshotBuilder,
    RawEntry, SnapshotBuildError, SnapshotPorts,
};
pub use policy_state::json_state_record_codec::JsonStateRecordCodec;
pub use policy_state::sha256_policy_digest::Sha256PolicyDigest;
pub use request_digest::Sha256RequestDigester;
pub use rng::SeededRng;
pub use token::caching_token_repository::CachingTokenRepository;
pub use token::jwt_access_token_verifier::{JwtAccessTokenVerifier, JwtSettings};
pub use token::jwt_key_set::{JwtKeyFileError, JwtKeySet};
pub use token::moka_token_memo::{MokaTokenMemo, TokenMemoSettings};
