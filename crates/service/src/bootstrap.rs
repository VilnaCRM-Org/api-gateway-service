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
use iam_application::http::IamState;
use iam_application::{
    GetChangeReceiptQueryHandler, GetIdempotentReplayQueryHandler, GetPolicyEpochQueryHandler,
};
use iam_domain::{
    AccessTokenVerifier, ChangeReceiptRepository, IdempotencyRepository, PolicyEpochRepository,
    SecurityAuditLog,
};
use iam_infrastructure::{
    JwtAccessTokenVerifier, JwtKeyFileError, PgChangeReceiptRepository, PgIdempotencyRepository,
    PgPolicyEpochRepository, PgSecurityAuditLog,
};
use shared_domain::{Clock, CommandBus, EventBus, QueryBus, UuidGenerator};
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
use crate::http::router::assemble;

/// Every driven port of the application.
#[derive(Debug)]
pub struct Adapters {
    /// Repository of the example context.
    pub repository: Arc<dyn ExampleApiResourceRepository>,
    /// Repository of the IAM policy epoch.
    pub policy_epochs: Arc<dyn PolicyEpochRepository>,
    /// The hash-chained IAM security audit log.
    pub security_audit_log: Arc<dyn SecurityAuditLog>,
    /// Reader of the receipts of committed IAM changes.
    pub change_receipts: Arc<dyn ChangeReceiptRepository>,
    /// Reader of the idempotency records of IAM writes.
    pub idempotency_records: Arc<dyn IdempotencyRepository>,
    /// Offline verifier of User service access tokens.
    pub access_tokens: Arc<dyn AccessTokenVerifier>,
    /// Health probes in the order database, cache, message broker.
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
            security_audit_log: Arc::new(PgSecurityAuditLog::new(pool.clone())),
            change_receipts: Arc::new(PgChangeReceiptRepository::new(pool.clone())),
            idempotency_records: Arc::new(PgIdempotencyRepository::new(pool.clone())),
            access_tokens,
            probes: vec![
                Arc::new(PostgresProbe::new(pool)),
                Arc::new(CacheProbe::new(cache)),
                Arc::new(SqsProbe::new(sqs)),
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

/// Registers every handler, builds the command and query buses, the state, the `GraphQL` schema
/// and the router with its middleware.
///
/// # Errors
///
/// Returns [`BootstrapError::DuplicateHandler`] when a message has two handlers.
pub fn router(adapters: Adapters, config: &Config) -> Result<Router, BootstrapError> {
    let create = CreateExampleApiResourceHandler::new(
        Arc::clone(&adapters.repository),
        adapters.event_bus,
        Arc::clone(&adapters.clock),
        Arc::clone(&adapters.uuid_generator),
    );
    let command_bus = register_commands(InMemoryCommandBus::new(), create)?;
    let bus = InMemoryQueryBus::new();
    let bus = register_queries(bus, &adapters.repository, &adapters.policy_epochs)?;
    let (receipts, keys) = (&adapters.change_receipts, &adapters.idempotency_records);
    let query_bus = register_change_queries(bus, receipts, keys, &adapters.clock)?;
    let commands: Arc<dyn CommandBus> = Arc::new(command_bus);
    let queries: Arc<dyn QueryBus> = Arc::new(query_bus);
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
    };
    let service = HealthService::new(adapters.probes, config.health_probe_timeout);
    let health_check = HealthCheckState {
        service: Arc::new(service),
    };
    let schema = schema::builder().data(some_module.clone()).finish();
    let state = AppState {
        health_check,
        some_module,
        iam,
    };
    Ok(assemble(state, schema, config))
}

#[cfg(test)]
mod tests;
