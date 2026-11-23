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
use iam_application::graphql::AsyncGraphQlSchemaParser;
use iam_application::http::IamState;
use iam_application::http::JsonOpenApiDocumentParser;
use iam_application::{
    ActivationReads, CreateGraphQlPermissionsCommandHandler,
    GetGraphQlPermissionsCreatedQueryHandler,
};
use iam_application::{AdministratorSafeguard, RevokeUserRoleReads, SafeguardPorts};
use iam_application::{
    AssignUserRoleCommandHandler, GetUserRoleQueryHandler, ListUserRolesQueryHandler,
    RevokeUserRoleCommandHandler, UpdateUserRoleCommandHandler,
};
use iam_application::{
    CreateRestPermissionsCommandHandler, GetRestPermissionsCreatedQueryHandler, RestActivationReads,
};
use iam_application::{
    CreateRoleCommandHandler, DeleteRoleCommandHandler, GetRoleQueryHandler, ListRolesQueryHandler,
    UpdateRoleCommandHandler,
};
use iam_application::{
    FindGraphQlSpecQueryHandler, GetGraphQlSpecDiffQueryHandler, GetGraphQlSpecQueryHandler,
    GetGraphQlSpecsQueryHandler, LoadGraphQlSpecCommandHandler,
};
use iam_application::{
    FindOpenApiSpecQueryHandler, GetOpenApiSpecDiffQueryHandler, GetOpenApiSpecQueryHandler,
    GetOpenApiSpecsQueryHandler, LoadOpenApiSpecCommandHandler,
};
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
use iam_application::{RegisterOwnSpecsCommand, RegisterOwnSpecsCommandHandler};
use iam_application::{ResolveSubjectTokenQueryHandler, ResolveTokenQueryHandler};
use iam_application::{RetireGraphQlSpecCommandHandler, RetireOpenApiSpecCommandHandler};
use iam_domain::GraphQlPermissionRepository;
use iam_domain::GraphQlSpecRepository;
use iam_domain::OpenApiSpecRepository;
use iam_domain::RestPermissionRepository;
use iam_domain::RoleRepository;
use iam_domain::SingletonLeadership;
use iam_domain::StartupLock;
use iam_domain::UserRoleRepository;
use iam_domain::{
    AccessTokenVerifier, ChangeReceiptRepository, IdempotencyRepository, PolicyEpochRepository,
    PolicyReadRepository, SecurityAuditLog,
};
use iam_domain::{IamUnitOfWork, OWN_SPECIFICATIONS_LOCK, RepositoryError, RequestDigester};
use iam_domain::{RevocationRepository, RevocationView, TokenMemo, TokenRepository};
use iam_infrastructure::KrafkaTopicInspector;
use iam_infrastructure::PgGraphQlPermissionRepository;
use iam_infrastructure::PgGraphQlSpecRepository;
use iam_infrastructure::PgOpenApiSpecRepository;
use iam_infrastructure::PgRestPermissionRepository;
use iam_infrastructure::PgRoleRepository;
use iam_infrastructure::PgUserRoleRepository;
use iam_infrastructure::Sha256RequestDigester;
use iam_infrastructure::{AdvisoryLockLeadership, PgIamUnitOfWork, PgStartupLock};
use iam_infrastructure::{
    CachingTokenRepository, MokaTokenMemo, PgRevocationRepository, PgRevocationView,
};
use iam_infrastructure::{
    JwtAccessTokenVerifier, JwtKeyFileError, PgChangeReceiptRepository, PgIdempotencyRepository,
    PgPolicyEpochRepository, PgPolicyReadRepository, PgSecurityAuditLog,
};
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

use crate::config::Config;
use crate::graphql::schema;
use crate::http::AppState;
use crate::http::router::assemble_with_iam_routes;
use crate::openapi::{self, ExportError};

pub use administrator::{AdministratorError, bootstrap_administrator};
pub use kafka_probe::KafkaProbe;
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
    /// The hash-chained IAM security audit log.
    pub security_audit_log: Arc<dyn SecurityAuditLog>,
    /// The cross-instance lock that serializes the startup registration of IAM's specifications.
    pub startup_lock: Arc<dyn StartupLock>,
    /// Fences each batch of a singleton task to one replica with an advisory lock.
    pub singleton_leadership: Arc<dyn SingletonLeadership>,
    /// Reader of the receipts of committed IAM changes.
    pub change_receipts: Arc<dyn ChangeReceiptRepository>,
    /// Reader of the idempotency records of IAM writes.
    pub idempotency_records: Arc<dyn IdempotencyRepository>,
    /// Reader of the IAM roles.
    pub roles: Arc<dyn RoleRepository>,
    /// Commits an administrative IAM change atomically.
    pub unit_of_work: Arc<dyn IamUnitOfWork>,
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
        let access_tokens = access_token_verifier(config, Arc::clone(&clock))?;
        let sqs = sqs_client(&config.sqs).await;
        let cache = Arc::new(MokaCache::new());
        Ok(Self {
            repository: Arc::new(PgExampleApiResourceRepository::new(pool.clone())),
            policy_epochs: Arc::new(PgPolicyEpochRepository::new(pool.clone())),
            policy_reads: Arc::new(PgPolicyReadRepository::new(pool.clone())),
            security_audit_log: Arc::new(PgSecurityAuditLog::new(pool.clone())),
            startup_lock: Arc::new(PgStartupLock::new(pool.clone())),
            singleton_leadership: Arc::new(AdvisoryLockLeadership::new(pool.clone())),
            change_receipts: Arc::new(PgChangeReceiptRepository::new(pool.clone())),
            idempotency_records: Arc::new(PgIdempotencyRepository::new(pool.clone())),
            roles: Arc::new(PgRoleRepository::new(pool.clone())),
            unit_of_work: Arc::new(PgIamUnitOfWork::new(pool.clone())),
            request_digester: Arc::new(Sha256RequestDigester),
            user_roles: Arc::new(PgUserRoleRepository::new(pool.clone())),
            graphql_specs: Arc::new(PgGraphQlSpecRepository::new(pool.clone())),
            openapi_specs: Arc::new(PgOpenApiSpecRepository::new(pool.clone())),
            graphql_permissions: Arc::new(PgGraphQlPermissionRepository::new(pool.clone())),
            rest_permissions: Arc::new(PgRestPermissionRepository::new(pool.clone())),
            tokens: token_repository(config, Arc::clone(&access_tokens), &clock, &pool),
            revocations: Arc::new(PgRevocationRepository::new(pool.clone())),
            access_tokens,
            probes: vec![
                Arc::new(PostgresProbe::new(pool)),
                Arc::new(CacheProbe::new(cache)),
                Arc::new(SqsProbe::new(sqs)),
                Arc::new(KafkaProbe::new(Arc::new(KrafkaTopicInspector::new(
                    &config.kafka,
                )))),
            ],
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
) -> Result<InMemoryCommandBus, BootstrapError> {
    let create = CreateRoleCommandHandler::new(
        Arc::clone(&adapters.unit_of_work),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    let update = UpdateRoleCommandHandler::new(
        Arc::clone(&adapters.roles),
        Arc::clone(&adapters.unit_of_work),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    let delete = DeleteRoleCommandHandler::new(
        Arc::clone(&adapters.roles),
        Arc::clone(&adapters.user_roles),
        Arc::clone(&adapters.unit_of_work),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    let set_permissions = SetRolePermissionsCommandHandler::new(
        SetRolePermissionsReads {
            roles: Arc::clone(&adapters.roles),
            graphql_permissions: Arc::clone(&adapters.graphql_permissions),
            rest_permissions: Arc::clone(&adapters.rest_permissions),
        },
        Arc::clone(&adapters.unit_of_work),
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

/// Registers the command handler that loads GraphQL specifications.
fn register_graphql_spec_commands(
    bus: InMemoryCommandBus,
    adapters: &Adapters,
) -> Result<InMemoryCommandBus, BootstrapError> {
    let load = LoadGraphQlSpecCommandHandler::new(
        Arc::clone(&adapters.unit_of_work),
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
) -> Result<InMemoryCommandBus, BootstrapError> {
    let reads = ActivationReads {
        specs: Arc::clone(&adapters.graphql_specs),
        permissions: Arc::clone(&adapters.graphql_permissions),
        roles: Arc::clone(&adapters.roles),
        policy_epochs: Arc::clone(&adapters.policy_epochs),
    };
    let activate = CreateGraphQlPermissionsCommandHandler::new(
        reads.clone(),
        Arc::clone(&adapters.unit_of_work),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    let retire = RetireGraphQlSpecCommandHandler::new(
        reads,
        Arc::clone(&adapters.unit_of_work),
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
) -> Result<InMemoryCommandBus, BootstrapError> {
    let reads = RestActivationReads {
        specs: Arc::clone(&adapters.openapi_specs),
        permissions: Arc::clone(&adapters.rest_permissions),
        roles: Arc::clone(&adapters.roles),
        policy_epochs: Arc::clone(&adapters.policy_epochs),
    };
    let activate = CreateRestPermissionsCommandHandler::new(
        reads.clone(),
        Arc::clone(&adapters.unit_of_work),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    let retire = RetireOpenApiSpecCommandHandler::new(
        reads,
        Arc::clone(&adapters.unit_of_work),
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
) -> Result<InMemoryCommandBus, BootstrapError> {
    let load = LoadOpenApiSpecCommandHandler::new(
        Arc::clone(&adapters.unit_of_work),
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
) -> Result<InMemoryCommandBus, BootstrapError> {
    let assign = AssignUserRoleCommandHandler::new(
        Arc::clone(&adapters.roles),
        Arc::clone(&adapters.unit_of_work),
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
        Arc::clone(&adapters.unit_of_work),
        Arc::clone(&safeguard),
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    let revoke = RevokeUserRoleCommandHandler::new(
        RevokeUserRoleReads {
            user_roles: Arc::clone(&adapters.user_roles),
            roles: Arc::clone(&adapters.roles),
        },
        Arc::clone(&adapters.unit_of_work),
        safeguard,
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    Ok(bus.register(assign)?.register(update)?.register(revoke)?)
}

/// Registers the query handlers of the IAM role assignments.
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
    Ok(bus.register(get)?.register(list)?)
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
    let commands = register_role_commands(commands, adapters)?;
    let commands = register_graphql_spec_commands(commands, adapters)?;
    let commands = register_graphql_activation_commands(commands, adapters)?;
    let commands = register_openapi_spec_commands(commands, adapters)?;
    let commands = register_rest_activation_commands(commands, adapters)?;
    let commands = register_user_role_commands(commands, adapters)?;
    let queries = InMemoryQueryBus::new();
    let queries = register_queries(queries, &adapters.repository, &adapters.policy_epochs)?;
    let (receipts, keys) = (&adapters.change_receipts, &adapters.idempotency_records);
    let queries = register_change_queries(queries, receipts, keys, &adapters.clock)?;
    let queries = register_role_queries(queries, &adapters.roles)?;
    let queries = register_graphql_spec_queries(queries, adapters)?;
    let queries = register_graphql_activation_queries(queries, adapters)?;
    let queries = register_graphql_permission_queries(queries, adapters)?;
    let queries = register_openapi_spec_queries(queries, adapters)?;
    let queries = register_rest_activation_queries(queries, adapters)?;
    let queries = register_rest_permission_queries(queries, adapters)?;
    let queries = register_user_role_queries(queries, adapters)?;
    let queries = register_token_queries(queries, &adapters.tokens, config)?;
    Ok((Arc::new(commands), Arc::new(queries)))
}

/// The buses of the registration: the loads and activations of both kinds of specification and the
/// lookups of an identical version.
fn registration_buses(adapters: &Adapters) -> Result<Buses, BootstrapError> {
    let commands = register_graphql_spec_commands(InMemoryCommandBus::new(), adapters)?;
    let commands = register_graphql_activation_commands(commands, adapters)?;
    let commands = register_openapi_spec_commands(commands, adapters)?;
    let commands = register_rest_activation_commands(commands, adapters)?;
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
/// and the router with its middleware.
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
        .finish();
    let state = AppState {
        health_check,
        some_module,
        iam,
    };
    Ok(assemble_with_iam_routes(state, schema, config, iam_routes))
}

pub mod gateway;

mod administrator;
mod kafka_probe;
mod tasks;

#[cfg(test)]
mod tests;
