//! The composition root: the only place where adapters meet use cases (AD-04).
//!
//! [`Adapters`] holds every driven port; [`router`] registers the handlers and builds the
//! application from it, so a test replaces any port by assigning a field or calling
//! [`Adapters::with_probe`].

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use health_check_application::HealthCheckState;
use health_check_application::HealthService;
use health_check_domain::HealthProbe;
use health_check_infrastructure::{CacheProbe, PostgresProbe, SqsProbe};
use iam_application::MaintenanceSettings;
use iam_application::PublishingUnitOfWork;
use iam_application::graphql::{AsyncGraphQlSchemaParser, IamAuthorizationExtension};
use iam_application::http::IamState;
use iam_application::http::JsonOpenApiDocumentParser;
use iam_application::{
    AccessDecisionService, ServiceCatalogLoader, ValidateAccessBatchQueryHandler,
    ValidateAccessQueryHandler,
};
use iam_application::{
    ActivationReads, CreateGraphQlPermissionsCommandHandler,
    GetGraphQlPermissionsCreatedQueryHandler,
};
use iam_application::{AdministratorSafeguard, RevokeUserRoleReads, SafeguardPorts};
use iam_application::{
    ApplyRouteConfigurationCommandHandler, GetRouteConfigurationQueryHandler,
    PreviewRouteConfigurationQueryHandler,
};
use iam_application::{
    AssignUserRoleCommandHandler, GetUserRolePermissionsQueryHandler, GetUserRoleQueryHandler,
    ListUserRolesQueryHandler, RevokeUserRoleCommandHandler, UpdateUserRoleCommandHandler,
};
use iam_application::{
    BulkDeletionPath, CreateRoleCommandHandler, DeleteRoleCommandHandler, GetRoleQueryHandler,
    ListRolesQueryHandler, UpdateRoleCommandHandler,
};
use iam_application::{
    CreateRatePolicyCommandHandler, DeleteRatePolicyCommandHandler, GetRatePolicyQueryHandler,
    ListRatePoliciesQueryHandler, UpdateRatePolicyCommandHandler,
};
use iam_application::{
    CreateRestPermissionsCommandHandler, GetRestPermissionsCreatedQueryHandler, RestActivationReads,
};
use iam_application::{
    CreateRouteCommandHandler, DeleteRouteCommandHandler, DeleteRoutePorts, GetRouteQueryHandler,
    ListRoutesQueryHandler, RoutePorts, UpdateRouteCommandHandler,
};
use iam_application::{
    CreateUpstreamCommandHandler, DeleteUpstreamCommandHandler, DeleteUpstreamPorts,
    GetUpstreamQueryHandler, ListUpstreamsQueryHandler, UpdateUpstreamCommandHandler,
};
use iam_application::{
    FindGraphQlSpecQueryHandler, GetGraphQlSpecDiffQueryHandler, GetGraphQlSpecQueryHandler,
    GetGraphQlSpecsQueryHandler, LoadGraphQlSpecCommandHandler,
};
use iam_application::{
    FindOpenApiSpecQueryHandler, GetOpenApiSpecDiffQueryHandler, GetOpenApiSpecQueryHandler,
    GetOpenApiSpecsQueryHandler, LoadOpenApiSpecCommandHandler,
};
use iam_application::{GetBulkOperationQueryHandler, ListBulkOperationsQueryHandler};
use iam_application::{
    GetChangeReceiptQueryHandler, GetIdempotentReplayQueryHandler, GetPolicyEpochQueryHandler,
};
use iam_application::{
    GetGraphQlPermissionQueryHandler, GetGraphQlPermissionsQueryHandler, PermissionReads,
};
use iam_application::{
    GetRestPermissionQueryHandler, GetRestPermissionsQueryHandler, RestPermissionReads,
};
use iam_application::{
    GetRolePermissionsQueryHandler, SetRolePermissionsCommandHandler, SetRolePermissionsReads,
};
use iam_application::{GuardReads, GuardedUnitOfWork};
use iam_application::{IamAccessGuard, RecordRejectedAttemptCommandHandler};
use iam_application::{PolicyTopicHead, ResyncPolicyCommandHandler, ResyncPolicyPorts};
use iam_application::{RegisterOwnSpecsCommand, RegisterOwnSpecsCommandHandler};
use iam_application::{ResolveSubjectTokenQueryHandler, ResolveTokenQueryHandler};
use iam_application::{RetireGraphQlSpecCommandHandler, RetireOpenApiSpecCommandHandler};
use iam_domain::GraphQlPermissionRepository;
use iam_domain::GraphQlSpecRepository;
use iam_domain::OpenApiSpecRepository;
use iam_domain::RatePolicyRepository;
use iam_domain::RestPermissionRepository;
use iam_domain::RoleRepository;
use iam_domain::RouteRepository;
use iam_domain::SingletonLeadership;
use iam_domain::StartupLock;
use iam_domain::UpstreamRepository;
use iam_domain::UserRoleRepository;
use iam_domain::{
    AccessTokenVerifier, ChangeReceiptRepository, IdempotencyRepository, PolicyEpochRepository,
    PolicyReadRepository, RejectedAttemptLog, SecurityAuditLog,
};
use iam_domain::{BulkOperationRepository, BulkRoleTargetStore};
use iam_domain::{IamUnitOfWork, OWN_SPECIFICATIONS_LOCK, RepositoryError, RequestDigester};
use iam_domain::{MaintenanceStore, TaskStateRepository};
use iam_domain::{PolicyLogTail, PolicyStateInventory};
use iam_domain::{RevocationRepository, RevocationView, TokenMemo, TokenRepository};
use iam_infrastructure::BufferedRejectedAttemptLog;
use iam_infrastructure::KrafkaTopicInspector;
use iam_infrastructure::MatchitRouteTableCompiler;
use iam_infrastructure::PgGraphQlPermissionRepository;
use iam_infrastructure::PgGraphQlSpecRepository;
use iam_infrastructure::PgOpenApiSpecRepository;
use iam_infrastructure::PgRatePolicyRepository;
use iam_infrastructure::PgRestPermissionRepository;
use iam_infrastructure::PgRoleRepository;
use iam_infrastructure::PgRouteRepository;
use iam_infrastructure::PgUpstreamRepository;
use iam_infrastructure::PgUserRoleRepository;
use iam_infrastructure::Sha256RequestDigester;
use iam_infrastructure::{
    AdvisoryLockLeadership, PgIamUnitOfWork, PgPropagationStore, PgStartupLock,
};
use iam_infrastructure::{
    CachingTokenRepository, MokaTokenMemo, PgRevocationRepository, PgRevocationView,
};
use iam_infrastructure::{JsonStateRecordCodec, KrafkaPolicyLogTail, PgPolicyStateInventory};
use iam_infrastructure::{
    JwtAccessTokenVerifier, JwtKeyFileError, PgBulkOperationRepository, PgBulkRoleTargetStore,
    PgChangeReceiptRepository, PgIdempotencyRepository, PgPolicyEpochRepository,
    PgPolicyReadRepository, PgSecurityAuditLog,
};
use iam_infrastructure::{PgMaintenanceStore, PgTaskStateRepository};
use shared_domain::{Clock, CommandBus, CommandHandler as _, EventBus, QueryBus, UuidGenerator};
use shared_infrastructure::bus::{
    DuplicateHandler, InMemoryCommandBus, InMemoryEventBus, InMemoryQueryBus,
};
use shared_infrastructure::cache::MokaCache;
use shared_infrastructure::clock::SystemClock;
use shared_infrastructure::id::UuidV7Generator;
use shared_infrastructure::messaging::sqs_client;
use shared_infrastructure::persistence::connect_lazy;
use some_module_application::http::SomeModuleState;
use some_module_application::{
    AuditExampleApiResourceCreated, CreateExampleApiResourceHandler, GetExampleApiResourceHandler,
    ListExampleApiResourcesHandler,
};
use some_module_domain::ExampleApiResourceRepository;
use some_module_infrastructure::PgExampleApiResourceRepository;

use crate::config::{BulkSettings, Config};
use crate::graphql::schema;
use crate::http::AppState;
use crate::http::router::assemble_with_iam_routes;
use crate::openapi::{self, ExportError};

pub use administrator::{
    AdministratorError, bootstrap_administrator, bootstrap_with_routes, repair_gateway_routes,
};
pub use anti_entropy::AntiEntropyAdapters;
pub use kafka_probe::KafkaProbe;
pub use outbox_relay::{OutboxRelayAdapters, forward_notifications};
pub use tasks::{TaskMode, TaskStop, TaskSupervisor, singleton_set, start_tasks};

/// Every driven port of the application.
#[derive(Debug)]
pub struct Adapters {
    /// Repository of the example context.
    pub repository: Arc<dyn ExampleApiResourceRepository>,
    /// Repository of the IAM policy epoch.
    pub policy_epochs: Arc<dyn PolicyEpochRepository>,
    /// Reader of the policy data of a decision in repeatable-read snapshots.
    pub policy_reads: Arc<dyn PolicyReadRepository>,
    /// Repository of the bulk operations and their progress.
    pub bulk_operations: Arc<dyn BulkOperationRepository>,
    /// The role that each role-deletion bulk operation deletes.
    pub bulk_targets: Arc<dyn BulkRoleTargetStore>,
    /// The chunk size and the rate cap of the bulk operation runner.
    pub bulk: BulkSettings,
    /// Lists the entities of the policy that a resync publishes.
    pub policy_inventory: Arc<dyn PolicyStateInventory>,
    /// The bounded reads of the state topic that a resync starts above.
    pub policy_tail: Arc<dyn PolicyLogTail>,
    /// The hash-chained IAM security audit log.
    pub security_audit_log: Arc<dyn SecurityAuditLog>,
    /// The per-replica buffer of refused IAM requests that the rejected-attempt writer appends to
    /// the audit log.
    pub rejected_attempts: Arc<dyn RejectedAttemptLog>,
    /// The cross-instance lock that serializes the startup registration of IAM's specifications.
    pub startup_lock: Arc<dyn StartupLock>,
    /// Fences each batch of a singleton task to one replica with an advisory lock.
    pub singleton_leadership: Arc<dyn SingletonLeadership>,
    /// Finds and removes what the maintenance task keeps small, and anchors the audit chain.
    pub maintenance_store: Arc<dyn MaintenanceStore>,
    /// Reader of what the committed batches of singleton tasks recorded.
    pub task_states: Arc<dyn TaskStateRepository>,
    /// How often the maintenance task runs and how long orphaned grants are kept.
    pub maintenance: MaintenanceSettings,
    /// The outbox relay and its wake-up; `None` runs no relay, as in a test that builds the
    /// application without Kafka.
    pub outbox_relay: Option<OutboxRelayAdapters>,
    /// Reader of the receipts of committed IAM changes.
    pub change_receipts: Arc<dyn ChangeReceiptRepository>,
    /// Reader of the idempotency records of IAM writes.
    pub idempotency_records: Arc<dyn IdempotencyRepository>,
    /// Reader of the IAM roles.
    pub roles: Arc<dyn RoleRepository>,
    /// Reader of the upstreams of the gateway configuration.
    pub upstreams: Arc<dyn UpstreamRepository>,
    /// Reader of the routes of the gateway configuration.
    pub routes: Arc<dyn RouteRepository>,
    /// Reader of the rate policies of the gateway configuration.
    pub rate_policies: Arc<dyn RatePolicyRepository>,
    /// Commits an administrative IAM change atomically.
    pub unit_of_work: Arc<dyn IamUnitOfWork>,
    /// Commits the changes of the REST and GraphQL writes and waits for the Kafka acknowledgement
    /// of their policy version (`PUBLISH_WAIT_TIMEOUT`); the bootstrap and the maintenance task
    /// commit through [`Self::unit_of_work`] and wait for nothing.
    pub write_unit_of_work: Arc<dyn IamUnitOfWork>,
    /// Digests the request of an idempotent IAM write.
    pub request_digester: Arc<dyn RequestDigester>,
    /// Reader of the IAM role assignments.
    pub user_roles: Arc<dyn UserRoleRepository>,
    /// Reader of the stored GraphQL specification versions.
    pub graphql_specs: Arc<dyn GraphQlSpecRepository>,
    /// Reader of the stored `OpenAPI` specification versions.
    pub openapi_specs: Arc<dyn OpenApiSpecRepository>,
    /// Reader of the GraphQL permission catalogue.
    pub graphql_permissions: Arc<dyn GraphQlPermissionRepository>,
    /// Reader of the REST permission catalogue.
    pub rest_permissions: Arc<dyn RestPermissionRepository>,
    /// Offline verifier of User service access tokens.
    pub access_tokens: Arc<dyn AccessTokenVerifier>,
    /// Resolver of bearer credentials: memoized verification and the revocation check.
    pub tokens: Arc<dyn TokenRepository>,
    /// Writer and reader of session revocations, cut-offs and consumed User service events.
    pub revocations: Arc<dyn RevocationRepository>,
    /// Health probes in the order database, cache, message broker, Kafka.
    pub probes: Vec<Arc<dyn HealthProbe>>,
    /// Bus the command handlers publish domain events to.
    pub event_bus: Arc<dyn EventBus>,
    /// Source of the current time.
    pub clock: Arc<dyn Clock>,
    /// Source of identifiers.
    pub uuid_generator: Arc<dyn UuidGenerator>,
}

/// The application could not be wired.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    /// The database settings are invalid.
    #[error("invalid database settings")]
    Database(#[from] sqlx::Error),
    /// A message has two handlers.
    #[error(transparent)]
    DuplicateHandler(#[from] DuplicateHandler),
    /// `JWT_PUBLIC_KEYS_FILE` holds no usable key set.
    #[error("invalid JWT_PUBLIC_KEYS_FILE")]
    KeyFile(#[from] JwtKeyFileError),
    /// The startup lock could not be taken.
    #[error("the startup lock could not be taken")]
    Lock(#[source] RepositoryError),
    /// IAM's own `OpenAPI` document could not be generated.
    #[error(transparent)]
    OwnDocument(#[from] ExportError),
    /// IAM's own specifications could not be registered.
    #[error("IAM's own specifications could not be registered")]
    Registration(#[from] iam_application::IamError),
}

/// How often the key file of `JWT_PUBLIC_KEYS_FILE` is checked for a replacement.
pub const KEY_FILE_POLL_INTERVAL: Duration = Duration::from_secs(5);

impl Adapters {
    /// The production wiring: a lazy connection pool, an in-process cache behind the cache
    /// probe, the SQS client and the in-process event bus.
    ///
    /// Nothing here touches the network; the first connection is made by the first request that
    /// needs it.
    ///
    /// # Errors
    ///
    /// Returns [`BootstrapError::Database`] when the database URL cannot be parsed and
    /// [`BootstrapError::KeyFile`] when the key file no longer holds a valid key set.
    pub async fn connect(config: &Config) -> Result<Self, BootstrapError> {
        let pool = connect_lazy(&config.database)?;
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let (unit_of_work, write_unit_of_work) = units_of_work(config, &pool, &clock);
        let access_tokens = access_token_verifier(config, Arc::clone(&clock))?;
        Ok(Self {
            repository: Arc::new(PgExampleApiResourceRepository::new(pool.clone())),
            policy_epochs: Arc::new(PgPolicyEpochRepository::new(pool.clone())),
            policy_reads: Arc::new(PgPolicyReadRepository::new(pool.clone())),
            bulk_operations: Arc::new(PgBulkOperationRepository::new(pool.clone())),
            bulk_targets: Arc::new(PgBulkRoleTargetStore::new(pool.clone())),
            bulk: config.bulk,
            policy_inventory: Arc::new(PgPolicyStateInventory::new(pool.clone())),
            policy_tail: Arc::new(KrafkaPolicyLogTail::new(config.kafka.clone())),
            security_audit_log: Arc::new(PgSecurityAuditLog::new(pool.clone())),
            rejected_attempts: Arc::new(BufferedRejectedAttemptLog::new()),
            startup_lock: Arc::new(PgStartupLock::new(pool.clone())),
            singleton_leadership: Arc::new(AdvisoryLockLeadership::new(pool.clone())),
            maintenance_store: Arc::new(
                PgMaintenanceStore::new(pool.clone())
                    .with_events_topic(config.kafka.events_topic.clone()),
            ),
            task_states: Arc::new(PgTaskStateRepository::new(pool.clone())),
            maintenance: config.maintenance,
            outbox_relay: Some(OutboxRelayAdapters::connect(config, &pool)?),
            change_receipts: Arc::new(PgChangeReceiptRepository::new(pool.clone())),
            idempotency_records: Arc::new(PgIdempotencyRepository::new(pool.clone())),
            roles: Arc::new(PgRoleRepository::new(pool.clone())),
            upstreams: Arc::new(PgUpstreamRepository::new(pool.clone())),
            routes: Arc::new(PgRouteRepository::new(pool.clone())),
            rate_policies: Arc::new(PgRatePolicyRepository::new(pool.clone())),
            unit_of_work,
            write_unit_of_work,
            request_digester: Arc::new(Sha256RequestDigester),
            user_roles: Arc::new(PgUserRoleRepository::new(pool.clone())),
            graphql_specs: Arc::new(PgGraphQlSpecRepository::new(pool.clone())),
            openapi_specs: Arc::new(PgOpenApiSpecRepository::new(pool.clone())),
            graphql_permissions: Arc::new(PgGraphQlPermissionRepository::new(pool.clone())),
            rest_permissions: Arc::new(PgRestPermissionRepository::new(pool.clone())),
            tokens: token_repository(config, Arc::clone(&access_tokens), &clock, &pool),
            revocations: Arc::new(PgRevocationRepository::new(pool.clone())),
            access_tokens,
            probes: probes(config, pool).await,
            event_bus: event_bus(),
            clock,
            uuid_generator: Arc::new(UuidV7Generator),
        })
    }

    /// Replaces the probe of the same dependency; the order and the other probes are kept.
    #[must_use]
    pub fn with_probe(mut self, probe: Arc<dyn HealthProbe>) -> Self {
        let dependency = probe.dependency();
        let position = self
            .probes
            .iter()
            .position(|slot| slot.dependency() == dependency);
        if let Some(slot) = position.and_then(|index| self.probes.get_mut(index)) {
            *slot = probe;
        }
        self
    }
}

/// The unit of work over PostgreSQL and the one of the published writes that wraps it.
fn units_of_work(
    config: &Config,
    pool: &sqlx::PgPool,
    clock: &Arc<dyn Clock>,
) -> (Arc<dyn IamUnitOfWork>, Arc<dyn IamUnitOfWork>) {
    let unit_of_work: Arc<dyn IamUnitOfWork> = Arc::new(
        PgIamUnitOfWork::new(pool.clone()).with_events_topic(config.kafka.events_topic.clone()),
    );
    let write_unit_of_work: Arc<dyn IamUnitOfWork> = Arc::new(PublishingUnitOfWork::new(
        Arc::clone(&unit_of_work),
        Arc::new(PgPropagationStore::new(pool.clone())),
        Arc::clone(clock),
        config.relay.publish_wait_timeout,
    ));
    (unit_of_work, write_unit_of_work)
}

/// The production probes: PostgreSQL over `pool`, an in-process cache, the SQS client and the
/// Kafka topic inspector.
async fn probes(config: &Config, pool: sqlx::PgPool) -> Vec<Arc<dyn HealthProbe>> {
    let sqs = sqs_client(&config.sqs).await;
    let cache = Arc::new(MokaCache::new());
    vec![
        Arc::new(PostgresProbe::new(pool)),
        Arc::new(CacheProbe::new(cache)),
        Arc::new(SqsProbe::new(sqs)),
        Arc::new(KafkaProbe::new(Arc::new(KrafkaTopicInspector::new(
            &config.kafka,
        )))),
    ]
}

/// The JWT verifier over the keys of `JWT_PUBLIC_KEYS_FILE`, with a watcher that reloads the file
/// every [`KEY_FILE_POLL_INTERVAL`] when it changed; the watcher ends with the verifier.
///
/// # Errors
///
/// Returns [`BootstrapError::KeyFile`] when the file holds no valid key set.
pub fn access_token_verifier(
    config: &Config,
    clock: Arc<dyn Clock>,
) -> Result<Arc<dyn AccessTokenVerifier>, BootstrapError> {
    let tokens = &config.tokens;
    let verifier = Arc::new(JwtAccessTokenVerifier::from_file(
        &tokens.public_keys_file,
        &tokens.jwt,
        clock,
    )?);
    drop(verifier.watch(KEY_FILE_POLL_INTERVAL));
    Ok(verifier)
}

/// The token repository over `verifier`: a memo sized by `TOKEN_MEMO_CAPACITY` and
/// `TOKEN_MEMO_MAX_TTL` on the `Clock` port, and the revocation state read from PostgreSQL.
#[must_use]
pub fn token_repository(
    config: &Config,
    verifier: Arc<dyn AccessTokenVerifier>,
    clock: &Arc<dyn Clock>,
    pool: &sqlx::PgPool,
) -> Arc<dyn TokenRepository> {
    let memo: Arc<dyn TokenMemo> =
        Arc::new(MokaTokenMemo::new(config.tokens.memo, Arc::clone(clock)));
    let revocations: Arc<dyn RevocationView> = Arc::new(PgRevocationView::new(pool.clone()));
    Arc::new(CachingTokenRepository::new(verifier, memo, revocations))
}

/// The in-process event bus with every subscriber registered.
#[must_use]
pub fn event_bus() -> Arc<dyn EventBus> {
    Arc::new(InMemoryEventBus::new().subscribe(AuditExampleApiResourceCreated))
}

/// Registers the command handlers of the example context.
fn register_commands(
    bus: InMemoryCommandBus,
    create: CreateExampleApiResourceHandler,
) -> Result<InMemoryCommandBus, BootstrapError> {
    Ok(bus.register(create)?)
}

/// Registers the query handlers of the example context and of the IAM context.
fn register_queries(
    bus: InMemoryQueryBus,
    repository: &Arc<dyn ExampleApiResourceRepository>,
    policy_epochs: &Arc<dyn PolicyEpochRepository>,
) -> Result<InMemoryQueryBus, BootstrapError> {
    let get = GetExampleApiResourceHandler::new(Arc::clone(repository));
    let list = ListExampleApiResourcesHandler::new(Arc::clone(repository));
    let policy_epoch = GetPolicyEpochQueryHandler::new(Arc::clone(policy_epochs));
    Ok(bus.register(get)?.register(list)?.register(policy_epoch)?)
}

/// Registers the command handlers of the IAM roles.
fn register_role_commands(
    bus: InMemoryCommandBus,
    adapters: &Adapters,
    unit_of_work: &Arc<dyn IamUnitOfWork>,
) -> Result<InMemoryCommandBus, BootstrapError> {
    let create = CreateRoleCommandHandler::new(
        Arc::clone(unit_of_work),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    let update = UpdateRoleCommandHandler::new(
        Arc::clone(&adapters.roles),
        Arc::clone(unit_of_work),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    let delete = DeleteRoleCommandHandler::new(
        Arc::clone(&adapters.roles),
        Arc::clone(&adapters.user_roles),
        Arc::clone(unit_of_work),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    )
    .with_bulk(BulkDeletionPath {
        operations: Arc::clone(&adapters.bulk_operations),
        targets: Arc::clone(&adapters.bulk_targets),
        chunker: adapters.bulk.chunker,
    });
    let set_permissions = SetRolePermissionsCommandHandler::new(
        SetRolePermissionsReads {
            roles: Arc::clone(&adapters.roles),
            graphql_permissions: Arc::clone(&adapters.graphql_permissions),
            rest_permissions: Arc::clone(&adapters.rest_permissions),
        },
        Arc::clone(unit_of_work),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    Ok(bus
        .register(create)?
        .register(update)?
        .register(delete)?
        .register(set_permissions)?)
}

/// Registers the query handlers of the IAM roles.
fn register_role_queries(
    bus: InMemoryQueryBus,
    roles: &Arc<dyn RoleRepository>,
) -> Result<InMemoryQueryBus, BootstrapError> {
    let get = GetRoleQueryHandler::new(Arc::clone(roles));
    let list = ListRolesQueryHandler::new(Arc::clone(roles));
    let permissions = GetRolePermissionsQueryHandler::new(Arc::clone(roles));
    Ok(bus.register(get)?.register(list)?.register(permissions)?)
}

/// Registers the command handlers of the rate policies of the gateway configuration.
fn register_rate_policy_commands(
    bus: InMemoryCommandBus,
    adapters: &Adapters,
    unit_of_work: &Arc<dyn IamUnitOfWork>,
) -> Result<InMemoryCommandBus, BootstrapError> {
    let create = CreateRatePolicyCommandHandler::new(
        Arc::clone(unit_of_work),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    let update = UpdateRatePolicyCommandHandler::new(
        Arc::clone(&adapters.rate_policies),
        Arc::clone(unit_of_work),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    let delete = DeleteRatePolicyCommandHandler::new(
        Arc::clone(&adapters.rate_policies),
        Arc::clone(&adapters.routes),
        Arc::clone(unit_of_work),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    Ok(bus.register(create)?.register(update)?.register(delete)?)
}

/// Registers the command handler of the policy resync.
fn register_resync_commands(
    bus: InMemoryCommandBus,
    adapters: &Adapters,
    unit_of_work: &Arc<dyn IamUnitOfWork>,
) -> Result<InMemoryCommandBus, BootstrapError> {
    let resync = ResyncPolicyCommandHandler::new(ResyncPolicyPorts {
        epochs: Arc::clone(&adapters.policy_epochs),
        inventory: Arc::clone(&adapters.policy_inventory),
        topic: PolicyTopicHead::new(
            Arc::clone(&adapters.policy_tail),
            Arc::new(JsonStateRecordCodec),
        ),
        unit_of_work: Arc::clone(unit_of_work),
        clock: Arc::clone(&adapters.clock),
        ids: Arc::clone(&adapters.uuid_generator),
    });
    Ok(bus.register(resync)?)
}

/// Registers the query handlers of the rate policies of the gateway configuration.
fn register_rate_policy_queries(
    bus: InMemoryQueryBus,
    rate_policies: &Arc<dyn RatePolicyRepository>,
) -> Result<InMemoryQueryBus, BootstrapError> {
    let get = GetRatePolicyQueryHandler::new(Arc::clone(rate_policies));
    let list = ListRatePoliciesQueryHandler::new(Arc::clone(rate_policies));
    Ok(bus.register(get)?.register(list)?)
}

/// Registers the command handlers of the upstreams of the gateway configuration.
fn register_upstream_commands(
    bus: InMemoryCommandBus,
    adapters: &Adapters,
    unit_of_work: &Arc<dyn IamUnitOfWork>,
) -> Result<InMemoryCommandBus, BootstrapError> {
    let create = CreateUpstreamCommandHandler::new(
        Arc::clone(unit_of_work),
        Arc::clone(&adapters.rejected_attempts),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    let update = UpdateUpstreamCommandHandler::new(
        Arc::clone(&adapters.upstreams),
        Arc::clone(unit_of_work),
        Arc::clone(&adapters.rejected_attempts),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    let delete = DeleteUpstreamCommandHandler::new(
        DeleteUpstreamPorts {
            upstreams: Arc::clone(&adapters.upstreams),
            routes: Arc::clone(&adapters.routes),
            unit_of_work: Arc::clone(unit_of_work),
            rejected_attempts: Arc::clone(&adapters.rejected_attempts),
        },
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    Ok(bus.register(create)?.register(update)?.register(delete)?)
}

/// The ports that the commands and the dry run of the routes read and write.
fn route_ports(adapters: &Adapters, unit_of_work: &Arc<dyn IamUnitOfWork>) -> RoutePorts {
    RoutePorts {
        upstreams: Arc::clone(&adapters.upstreams),
        rate_policies: Arc::clone(&adapters.rate_policies),
        routes: Arc::clone(&adapters.routes),
        compiler: Arc::new(MatchitRouteTableCompiler),
        policies: Arc::clone(&adapters.policy_reads),
        unit_of_work: Arc::clone(unit_of_work),
        rejected_attempts: Arc::clone(&adapters.rejected_attempts),
    }
}

/// Registers the command handlers of the routes of the gateway configuration; a route
/// configuration holds at most `max_routes` routes.
fn register_route_commands(
    bus: InMemoryCommandBus,
    adapters: &Adapters,
    unit_of_work: &Arc<dyn IamUnitOfWork>,
    max_routes: usize,
) -> Result<InMemoryCommandBus, BootstrapError> {
    let ports = || route_ports(adapters, unit_of_work);
    let apply = ApplyRouteConfigurationCommandHandler::new(
        ports(),
        max_routes,
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    let create = CreateRouteCommandHandler::new(
        ports(),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    let update = UpdateRouteCommandHandler::new(
        ports(),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    let delete = DeleteRouteCommandHandler::new(
        DeleteRoutePorts {
            routes: Arc::clone(&adapters.routes),
            unit_of_work: Arc::clone(unit_of_work),
            rejected_attempts: Arc::clone(&adapters.rejected_attempts),
        },
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    Ok(bus
        .register(create)?
        .register(update)?
        .register(delete)?
        .register(apply)?)
}

/// Registers the query handlers of the routes of the gateway configuration; the dry run of a route
/// configuration accepts at most `max_routes` routes.
fn register_route_queries(
    bus: InMemoryQueryBus,
    adapters: &Adapters,
    unit_of_work: &Arc<dyn IamUnitOfWork>,
    max_routes: usize,
) -> Result<InMemoryQueryBus, BootstrapError> {
    let routes = &adapters.routes;
    let get = GetRouteQueryHandler::new(Arc::clone(routes));
    let list = ListRoutesQueryHandler::new(Arc::clone(routes));
    let configuration = GetRouteConfigurationQueryHandler::new(Arc::clone(routes));
    let preview = PreviewRouteConfigurationQueryHandler::new(
        route_ports(adapters, unit_of_work),
        max_routes,
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    Ok(bus
        .register(get)?
        .register(list)?
        .register(configuration)?
        .register(preview)?)
}

/// Registers the query handlers of the upstreams of the gateway configuration.
fn register_upstream_queries(
    bus: InMemoryQueryBus,
    upstreams: &Arc<dyn UpstreamRepository>,
) -> Result<InMemoryQueryBus, BootstrapError> {
    let get = GetUpstreamQueryHandler::new(Arc::clone(upstreams));
    let list = ListUpstreamsQueryHandler::new(Arc::clone(upstreams));
    Ok(bus.register(get)?.register(list)?)
}

/// Registers the query handlers that read the result of an IAM write: its change receipt and the
/// idempotent replay of a repeated write.
fn register_change_queries(
    bus: InMemoryQueryBus,
    change_receipts: &Arc<dyn ChangeReceiptRepository>,
    idempotency_records: &Arc<dyn IdempotencyRepository>,
    clock: &Arc<dyn Clock>,
) -> Result<InMemoryQueryBus, BootstrapError> {
    let receipt = GetChangeReceiptQueryHandler::new(Arc::clone(change_receipts));
    let replay = GetIdempotentReplayQueryHandler::new(
        Arc::clone(idempotency_records),
        Arc::clone(change_receipts),
        Arc::clone(clock),
    );
    Ok(bus.register(receipt)?.register(replay)?)
}

/// Registers the handlers that resolve bearer tokens: the one that authenticates the callers of
/// IAM's own API, and the one behind the token-resolution operation.
///
/// Both resolve tokens through the token repository; only the first applies the caller rule of
/// `JWT_CALLER_AUDIENCE` and `JWT_SERVICE_TOKEN_MAX_LIFETIME`.
fn register_token_queries(
    bus: InMemoryQueryBus,
    tokens: &Arc<dyn TokenRepository>,
    config: &Config,
) -> Result<InMemoryQueryBus, BootstrapError> {
    let resolve = ResolveTokenQueryHandler::new(Arc::clone(tokens), config.tokens.callers.clone());
    let subject = ResolveSubjectTokenQueryHandler::new(Arc::clone(tokens));
    Ok(bus.register(resolve)?.register(subject)?)
}

/// The decision path over the ports of the application: the access-validation operations and the
/// authorization of IAM's own operations share its rule.
fn decision_service(adapters: &Adapters) -> Arc<AccessDecisionService> {
    Arc::new(AccessDecisionService::new(
        Arc::clone(&adapters.tokens),
        ServiceCatalogLoader::new(Arc::clone(&adapters.policy_reads)),
        Arc::clone(&adapters.policy_reads),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    ))
}

/// Registers the command handler that offers the refusals of IAM's operations to the buffer of the
/// audit log.
fn register_rejected_attempt_commands(
    bus: InMemoryCommandBus,
    adapters: &Adapters,
) -> Result<InMemoryCommandBus, BootstrapError> {
    let record = RecordRejectedAttemptCommandHandler::new(
        Arc::clone(&adapters.rejected_attempts),
        Arc::clone(&adapters.clock),
    );
    Ok(bus.register(record)?)
}

/// Registers the handlers behind the access-validation operations, single and batch.
///
/// The decision path reads the subject's token through the token repository and the catalogue and
/// the policy of the subject through the policy read repository, with the `Clock` and
/// `UuidGenerator` ports of the application; the handler reads the policy epoch for a
/// `minPolicyVersion`.
fn register_access_validation_queries(
    bus: InMemoryQueryBus,
    adapters: &Adapters,
) -> Result<InMemoryQueryBus, BootstrapError> {
    let decisions = decision_service(adapters);
    let validate = ValidateAccessQueryHandler::new(
        Arc::clone(&decisions),
        Arc::clone(&adapters.policy_epochs),
    );
    let batch = ValidateAccessBatchQueryHandler::new(
        decisions,
        Arc::clone(&adapters.policy_epochs),
        Arc::clone(&adapters.tokens),
    );
    Ok(bus.register(validate)?.register(batch)?)
}

/// Registers the command handler that loads GraphQL specifications.
fn register_graphql_spec_commands(
    bus: InMemoryCommandBus,
    adapters: &Adapters,
    unit_of_work: &Arc<dyn IamUnitOfWork>,
) -> Result<InMemoryCommandBus, BootstrapError> {
    let load = LoadGraphQlSpecCommandHandler::new(
        Arc::clone(unit_of_work),
        Arc::new(AsyncGraphQlSchemaParser),
        Arc::clone(&adapters.request_digester),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    Ok(bus.register(load)?)
}

/// Registers the query handlers that read GraphQL specifications: the lookup of an identical upload,
/// the version with its diff, the version alone and the list of versions.
fn register_graphql_spec_queries(
    bus: InMemoryQueryBus,
    adapters: &Adapters,
) -> Result<InMemoryQueryBus, BootstrapError> {
    let find = FindGraphQlSpecQueryHandler::new(Arc::clone(&adapters.graphql_specs));
    let diff = GetGraphQlSpecDiffQueryHandler::new(
        Arc::clone(&adapters.graphql_specs),
        Arc::clone(&adapters.roles),
    );
    let one = GetGraphQlSpecQueryHandler::new(Arc::clone(&adapters.graphql_specs));
    let list = GetGraphQlSpecsQueryHandler::new(Arc::clone(&adapters.graphql_specs));
    Ok(bus
        .register(find)?
        .register(diff)?
        .register(one)?
        .register(list)?)
}

/// Registers the command handler that activates GraphQL specifications.
fn register_graphql_activation_commands(
    bus: InMemoryCommandBus,
    adapters: &Adapters,
    unit_of_work: &Arc<dyn IamUnitOfWork>,
) -> Result<InMemoryCommandBus, BootstrapError> {
    let reads = ActivationReads {
        specs: Arc::clone(&adapters.graphql_specs),
        permissions: Arc::clone(&adapters.graphql_permissions),
        roles: Arc::clone(&adapters.roles),
        policy_epochs: Arc::clone(&adapters.policy_epochs),
    };
    let activate = CreateGraphQlPermissionsCommandHandler::new(
        reads.clone(),
        Arc::clone(unit_of_work),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    let retire = RetireGraphQlSpecCommandHandler::new(
        reads,
        Arc::clone(unit_of_work),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    Ok(bus.register(activate)?.register(retire)?)
}

/// Registers the query handler that reads the keys an activation of a GraphQL specification created.
fn register_graphql_activation_queries(
    bus: InMemoryQueryBus,
    adapters: &Adapters,
) -> Result<InMemoryQueryBus, BootstrapError> {
    let created =
        GetGraphQlPermissionsCreatedQueryHandler::new(Arc::clone(&adapters.graphql_permissions));
    Ok(bus.register(created)?)
}

/// Registers the query handlers that read the GraphQL permission catalogue: the list and one entry.
fn register_graphql_permission_queries(
    bus: InMemoryQueryBus,
    adapters: &Adapters,
) -> Result<InMemoryQueryBus, BootstrapError> {
    let reads = PermissionReads {
        permissions: Arc::clone(&adapters.graphql_permissions),
        specs: Arc::clone(&adapters.graphql_specs),
        roles: Arc::clone(&adapters.roles),
    };
    let list = GetGraphQlPermissionsQueryHandler::new(reads.clone());
    let one = GetGraphQlPermissionQueryHandler::new(reads);
    Ok(bus.register(list)?.register(one)?)
}

/// Registers the query handlers that read the REST permission catalogue.
fn register_rest_permission_queries(
    bus: InMemoryQueryBus,
    adapters: &Adapters,
) -> Result<InMemoryQueryBus, BootstrapError> {
    let reads = RestPermissionReads {
        permissions: Arc::clone(&adapters.rest_permissions),
        specs: Arc::clone(&adapters.openapi_specs),
        roles: Arc::clone(&adapters.roles),
    };
    let list = GetRestPermissionsQueryHandler::new(reads.clone());
    let one = GetRestPermissionQueryHandler::new(reads);
    Ok(bus.register(list)?.register(one)?)
}

/// Registers the command handler that activates `OpenAPI` specifications.
fn register_rest_activation_commands(
    bus: InMemoryCommandBus,
    adapters: &Adapters,
    unit_of_work: &Arc<dyn IamUnitOfWork>,
) -> Result<InMemoryCommandBus, BootstrapError> {
    let reads = RestActivationReads {
        specs: Arc::clone(&adapters.openapi_specs),
        permissions: Arc::clone(&adapters.rest_permissions),
        roles: Arc::clone(&adapters.roles),
        policy_epochs: Arc::clone(&adapters.policy_epochs),
    };
    let activate = CreateRestPermissionsCommandHandler::new(
        reads.clone(),
        Arc::clone(unit_of_work),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    let retire = RetireOpenApiSpecCommandHandler::new(
        reads,
        Arc::clone(unit_of_work),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    Ok(bus.register(activate)?.register(retire)?)
}

/// Registers the query handler that reads the keys an activation of an `OpenAPI` specification
/// created.
fn register_rest_activation_queries(
    bus: InMemoryQueryBus,
    adapters: &Adapters,
) -> Result<InMemoryQueryBus, BootstrapError> {
    let created =
        GetRestPermissionsCreatedQueryHandler::new(Arc::clone(&adapters.rest_permissions));
    Ok(bus.register(created)?)
}

/// Registers the command handler that loads `OpenAPI` specifications.
fn register_openapi_spec_commands(
    bus: InMemoryCommandBus,
    adapters: &Adapters,
    unit_of_work: &Arc<dyn IamUnitOfWork>,
) -> Result<InMemoryCommandBus, BootstrapError> {
    let load = LoadOpenApiSpecCommandHandler::new(
        Arc::clone(unit_of_work),
        Arc::new(JsonOpenApiDocumentParser),
        Arc::clone(&adapters.request_digester),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    Ok(bus.register(load)?)
}

/// Registers the query handlers that read `OpenAPI` specifications: the lookup of an identical
/// upload, the version with its diff, the version alone and the list of versions.
fn register_openapi_spec_queries(
    bus: InMemoryQueryBus,
    adapters: &Adapters,
) -> Result<InMemoryQueryBus, BootstrapError> {
    let find = FindOpenApiSpecQueryHandler::new(Arc::clone(&adapters.openapi_specs));
    let diff = GetOpenApiSpecDiffQueryHandler::new(
        Arc::clone(&adapters.openapi_specs),
        Arc::clone(&adapters.roles),
    );
    let one = GetOpenApiSpecQueryHandler::new(Arc::clone(&adapters.openapi_specs));
    let list = GetOpenApiSpecsQueryHandler::new(Arc::clone(&adapters.openapi_specs));
    Ok(bus
        .register(find)?
        .register(diff)?
        .register(one)?
        .register(list)?)
}

/// Registers the command handlers of the IAM role assignments.
fn register_user_role_commands(
    bus: InMemoryCommandBus,
    adapters: &Adapters,
    unit_of_work: &Arc<dyn IamUnitOfWork>,
) -> Result<InMemoryCommandBus, BootstrapError> {
    let assign = AssignUserRoleCommandHandler::new(
        Arc::clone(&adapters.roles),
        Arc::clone(unit_of_work),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    let safeguard = Arc::new(AdministratorSafeguard::new(
        SafeguardPorts {
            roles: Arc::clone(&adapters.roles),
            user_roles: Arc::clone(&adapters.user_roles),
            audit_log: Arc::clone(&adapters.security_audit_log),
            startup_lock: Arc::clone(&adapters.startup_lock),
        },
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    ));
    let update = UpdateUserRoleCommandHandler::new(
        Arc::clone(&adapters.user_roles),
        Arc::clone(unit_of_work),
        Arc::clone(&safeguard),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    let revoke = RevokeUserRoleCommandHandler::new(
        RevokeUserRoleReads {
            user_roles: Arc::clone(&adapters.user_roles),
            roles: Arc::clone(&adapters.roles),
        },
        Arc::clone(unit_of_work),
        safeguard,
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    Ok(bus.register(assign)?.register(update)?.register(revoke)?)
}

/// Registers the query handlers of the IAM role assignments and of the effective permissions of a
/// user, which `iam-control` composes from PostgreSQL through the policy read repository.
fn register_user_role_queries(
    bus: InMemoryQueryBus,
    adapters: &Adapters,
) -> Result<InMemoryQueryBus, BootstrapError> {
    let get = GetUserRoleQueryHandler::new(
        Arc::clone(&adapters.user_roles),
        Arc::clone(&adapters.roles),
    );
    let list = ListUserRolesQueryHandler::new(
        Arc::clone(&adapters.user_roles),
        Arc::clone(&adapters.roles),
        Arc::clone(&adapters.clock),
    );
    let effective = GetUserRolePermissionsQueryHandler::new(
        Arc::clone(&adapters.policy_reads),
        Arc::clone(&adapters.roles),
        Arc::clone(&adapters.clock),
    );
    let bulk = GetBulkOperationQueryHandler::new(Arc::clone(&adapters.bulk_operations));
    let bulk_list = ListBulkOperationsQueryHandler::new(Arc::clone(&adapters.bulk_operations));
    Ok(bus
        .register(get)?
        .register(list)?
        .register(effective)?
        .register(bulk)?
        .register(bulk_list)?)
}

/// The unit of work of the administrative writes: it runs the escalation and specification-scope
/// guards of a change against the stored policy of its actor before it commits.
fn guarded_unit_of_work(adapters: &Adapters) -> Arc<dyn IamUnitOfWork> {
    Arc::new(GuardedUnitOfWork::new(
        Arc::clone(&adapters.write_unit_of_work),
        GuardReads {
            policy: Arc::clone(&adapters.policy_reads),
            roles: Arc::clone(&adapters.roles),
            rest_permissions: Arc::clone(&adapters.rest_permissions),
            graphql_permissions: Arc::clone(&adapters.graphql_permissions),
            audit_log: Arc::clone(&adapters.security_audit_log),
        },
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    ))
}

/// The command bus and the query bus of the service.
type Buses = (Arc<dyn CommandBus>, Arc<dyn QueryBus>);

/// The command bus and the query bus with every handler registered.
fn register_buses(adapters: &Adapters, config: &Config) -> Result<Buses, BootstrapError> {
    let create = CreateExampleApiResourceHandler::new(
        Arc::clone(&adapters.repository),
        Arc::clone(&adapters.event_bus),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    let commands = register_commands(InMemoryCommandBus::new(), create)?;
    let guarded = guarded_unit_of_work(adapters);
    let commands = register_role_commands(commands, adapters, &guarded)?;
    let commands = register_upstream_commands(commands, adapters, &guarded)?;
    let max_routes = config.route_configuration_max_routes;
    let commands = register_route_commands(commands, adapters, &guarded, max_routes)?;
    let commands = register_rate_policy_commands(commands, adapters, &guarded)?;
    let commands = register_resync_commands(commands, adapters, &guarded)?;
    let commands = register_graphql_spec_commands(commands, adapters, &guarded)?;
    let commands = register_graphql_activation_commands(commands, adapters, &guarded)?;
    let commands = register_openapi_spec_commands(commands, adapters, &guarded)?;
    let commands = register_rest_activation_commands(commands, adapters, &guarded)?;
    let commands = register_user_role_commands(commands, adapters, &guarded)?;
    let commands = register_rejected_attempt_commands(commands, adapters)?;
    let queries = InMemoryQueryBus::new();
    let queries = register_queries(queries, &adapters.repository, &adapters.policy_epochs)?;
    let (receipts, keys) = (&adapters.change_receipts, &adapters.idempotency_records);
    let queries = register_change_queries(queries, receipts, keys, &adapters.clock)?;
    let queries = register_role_queries(queries, &adapters.roles)?;
    let queries = register_upstream_queries(queries, &adapters.upstreams)?;
    let queries = register_route_queries(queries, adapters, &guarded, max_routes)?;
    let queries = register_rate_policy_queries(queries, &adapters.rate_policies)?;
    let queries = register_graphql_spec_queries(queries, adapters)?;
    let queries = register_graphql_activation_queries(queries, adapters)?;
    let queries = register_graphql_permission_queries(queries, adapters)?;
    let queries = register_openapi_spec_queries(queries, adapters)?;
    let queries = register_rest_activation_queries(queries, adapters)?;
    let queries = register_rest_permission_queries(queries, adapters)?;
    let queries = register_user_role_queries(queries, adapters)?;
    let queries = register_token_queries(queries, &adapters.tokens, config)?;
    let queries = register_access_validation_queries(queries, adapters)?;
    Ok((Arc::new(commands), Arc::new(queries)))
}

/// The buses of the registration: the loads and activations of both kinds of specification and the
/// lookups of an identical version.
fn registration_buses(adapters: &Adapters) -> Result<Buses, BootstrapError> {
    let bus = InMemoryCommandBus::new();
    let commands = register_graphql_spec_commands(bus, adapters, &adapters.unit_of_work)?;
    let commands =
        register_graphql_activation_commands(commands, adapters, &adapters.unit_of_work)?;
    let commands = register_openapi_spec_commands(commands, adapters, &adapters.unit_of_work)?;
    let commands = register_rest_activation_commands(commands, adapters, &adapters.unit_of_work)?;
    let find_graphql = FindGraphQlSpecQueryHandler::new(Arc::clone(&adapters.graphql_specs));
    let find_openapi = FindOpenApiSpecQueryHandler::new(Arc::clone(&adapters.openapi_specs));
    let queries = InMemoryQueryBus::new()
        .register(find_graphql)?
        .register(find_openapi)?;
    Ok((Arc::new(commands), Arc::new(queries)))
}

/// Registers IAM's own specifications in its catalogue: the operations of the generated `OpenAPI`
/// document tagged `iam` and the GraphQL operations that IAM owns, as `system:startup`.
///
/// The registration is additive and idempotent by content hash. It runs under a PostgreSQL
/// transaction-level advisory lock, so of several instances that start together one registers and
/// the others find the active version. `service serve` calls it after [`Adapters::connect`], and
/// so does every test that builds the application from the adapters.
///
/// # Errors
///
/// Returns [`BootstrapError::Lock`] when the lock cannot be taken,
/// [`BootstrapError::OwnDocument`] when the document cannot be generated,
/// [`BootstrapError::DuplicateHandler`] when a message has two handlers and
/// [`BootstrapError::Registration`] when the database refuses the registration.
pub async fn register_iam_specs(adapters: &Adapters) -> Result<(), BootstrapError> {
    let command = RegisterOwnSpecsCommand {
        openapi_document: openapi::iam_document()?,
        graphql_sdl: schema::iam_sdl(),
    };
    register_iam_documents(adapters, command).await
}

/// [`register_iam_specs`] for the documents of `command`: the same registration under the same
/// lock, for the tests that register the contract of another build.
///
/// # Errors
///
/// The errors of [`register_iam_specs`], except [`BootstrapError::OwnDocument`].
pub async fn register_iam_documents(
    adapters: &Adapters,
    command: RegisterOwnSpecsCommand,
) -> Result<(), BootstrapError> {
    let _lock = adapters
        .startup_lock
        .acquire(OWN_SPECIFICATIONS_LOCK)
        .await
        .map_err(BootstrapError::Lock)?;
    registration_handler(adapters)?.handle(command).await?;
    Ok(())
}

/// The handler of the registration over the buses of [`registration_buses`].
fn registration_handler(
    adapters: &Adapters,
) -> Result<RegisterOwnSpecsCommandHandler, BootstrapError> {
    let (commands, queries) = registration_buses(adapters)?;
    Ok(RegisterOwnSpecsCommandHandler::new(
        commands,
        queries,
        Arc::clone(&adapters.request_digester),
        Arc::clone(&adapters.uuid_generator),
    ))
}

/// Registers every handler, builds the command and query buses, the state, the `GraphQL` schema
/// (with the authorization of IAM's own fields) and the router with its middleware.
///
/// # Errors
///
/// Returns [`BootstrapError::DuplicateHandler`] when a message has two handlers.
pub fn router(adapters: Adapters, config: &Config) -> Result<Router, BootstrapError> {
    router_with_iam_routes(adapters, config, Router::new())
}

/// [`router`] with `iam_routes` mounted on the IAM router, behind the authentication of IAM's
/// callers.
///
/// The IAM context registers its own operations in its router, so this serves the tests that need
/// a protected route before it has one.
///
/// # Errors
///
/// Returns [`BootstrapError::DuplicateHandler`] when a message has two handlers.
pub fn router_with_iam_routes(
    adapters: Adapters,
    config: &Config,
    iam_routes: Router<AppState>,
) -> Result<Router, BootstrapError> {
    let (commands, queries) = register_buses(&adapters, config)?;
    let guard = Arc::new(IamAccessGuard::new(
        decision_service(&adapters),
        Arc::clone(&commands),
    ));
    let some_module = SomeModuleState {
        command_bus: Arc::clone(&commands),
        query_bus: Arc::clone(&queries),
        uuid_generator: Arc::clone(&adapters.uuid_generator),
    };
    let iam = IamState {
        command_bus: commands,
        query_bus: queries,
        uuid_generator: adapters.uuid_generator,
        clock: adapters.clock,
        request_digester: adapters.request_digester,
    };
    let service = HealthService::new(adapters.probes, config.health_probe_timeout);
    let health_check = HealthCheckState {
        service: Arc::new(service),
    };
    let schema = schema::builder()
        .data(some_module.clone())
        .data(iam.clone())
        .extension(IamAuthorizationExtension::new(Arc::clone(&guard)))
        .finish();
    let state = AppState {
        health_check,
        some_module,
        iam,
    };
    Ok(assemble_with_iam_routes(
        state, schema, config, iam_routes, guard,
    ))
}

pub mod gateway;

mod administrator;
mod anti_entropy;
mod kafka_probe;
mod outbox_relay;
mod tasks;

#[cfg(test)]
mod tests;
