//! Typed configuration of the service, parsed and validated from the command-line arguments.
//!
//! [`Config::from_args`] collects every problem instead of stopping at the first one. A problem
//! names the environment variable and a reason that never contains a value, so a secret that is
//! malformed is not echoed.

use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use axum::http::Uri;
use axum::http::uri::Authority;
use iam_application::{AntiEntropySettings, MaintenanceSettings};
use iam_domain::{BulkChunker, BulkPacing};
use iam_domain::{
    CallerTokenRule, ClassBudgets, ConfigGates, DEFAULT_CHANNEL_CAPACITY, InvalidAccessLogSetting,
    SampleRate, TokenLifetimeRule, Zone, parse_channel_capacity,
};
use iam_infrastructure::{
    JwtKeySet, JwtSettings, KafkaSecret, KafkaSecurity, KafkaSettings, ProbeCredentials,
    SaslMechanism, StaticEndpointWatch, TokenMemoSettings, ValkeyEndpoint,
};
use shared_infrastructure::messaging::SqsSettings;
use shared_infrastructure::persistence::{
    MAX_STATEMENT_TIMEOUT, MIN_STATEMENT_TIMEOUT, PostgresSettings,
};
use sqlx::postgres::PgConnectOptions;
use tracing_subscriber::EnvFilter;

use crate::bootstrap::gateway::listener;
use crate::cli::{
    AntiEntropyArgs, BulkArgs, DatabaseArgs, GatewayArgs, KafkaArgs, MaintenanceArgs, MigrateArgs,
    RelayArgs, ServeArgs, TokenArgs,
};

mod access_log_query;
mod audit_lane;

use self::access_log_query::access_log_query_settings;
use self::audit_lane::lane_bounds;

pub use access_log_query::{
    AccessLogQuerySettings, DEFAULT_LOKI_QUERY_URL, DEFAULT_MAX_RANGE, DEFAULT_TIMEOUT,
};
pub use audit_lane::{
    AuditLaneSettings, DEFAULT_LOKI_PUSH_URL, DEFAULT_LOKI_TENANT_ID, DEFAULT_MAX_PENDING,
    env_label,
};

/// The largest accepted `JWT_CLOCK_SKEW`.
const MAX_CLOCK_SKEW: Duration = Duration::from_mins(1);

/// The smallest accepted `TOKEN_MEMO_CAPACITY`.
const MIN_TOKEN_MEMO_CAPACITY: u64 = 1_000;

/// The largest accepted `JWT_SERVICE_TOKEN_MAX_LIFETIME`.
const MAX_SERVICE_TOKEN_LIFETIME: Duration = Duration::from_hours(1);

/// The `JWT_SERVICE_TOKEN_MAX_LIFETIME` of a configuration that does not set it, capped at
/// `MAX_TOKEN_LIFETIME`.
const DEFAULT_SERVICE_TOKEN_MAX_LIFETIME: Duration = Duration::from_mins(15);

/// The `TOKEN_MEMO_MAX_TTL` of a configuration that does not set it.
const DEFAULT_TOKEN_MEMO_MAX_TTL: Duration = Duration::from_mins(15);

/// Deployment environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppEnv {
    /// Local development: the GraphQL explorer is served.
    Dev,
    /// Automated tests.
    Test,
    /// Production.
    Prod,
}

/// One invalid or missing variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigProblem {
    /// Name of the environment variable.
    pub variable: &'static str,
    /// What is wrong with it; never contains the value.
    pub reason: String,
}

/// Every problem of a configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the configuration is invalid ({} problem(s))", .0.len())]
pub struct ConfigErrors(Vec<ConfigProblem>);

impl ConfigErrors {
    /// The problems in the order of the variables of the configuration table; the rules that
    /// relate two variables come last.
    #[must_use]
    pub fn problems(&self) -> &[ConfigProblem] {
        &self.0
    }
}

/// The validated configuration of `serve` and `check-config`.
#[derive(Debug, Clone)]
pub struct Config {
    /// Deployment environment.
    pub app_env: AppEnv,
    /// Address to listen on.
    pub host: IpAddr,
    /// Port to listen on; 0 selects any free port.
    pub port: u16,
    /// `tracing` filter directives.
    pub log_level: String,
    /// PostgreSQL pool settings.
    pub database: PostgresSettings,
    /// SQS client settings.
    pub sqs: SqsSettings,
    /// Timeout of one health probe.
    pub health_probe_timeout: Duration,
    /// Budget of one HTTP request.
    pub request_timeout: Duration,
    /// Largest accepted request body in bytes.
    pub max_body_bytes: usize,
    /// Time the in-flight requests get to finish after a termination signal.
    pub shutdown_grace_period: Duration,
    /// Offline validation of User service access tokens.
    pub tokens: TokenSettings,
    /// The control-plane Kafka connection and the topics it works on.
    pub kafka: KafkaSettings,
    /// How often the maintenance task runs and how long orphaned grants are kept.
    pub maintenance: MaintenanceSettings,
    /// The connection that wakes the outbox relay and the timeout of its transactions.
    pub relay: RelaySettings,
    /// How often the anti-entropy task checks the head and rebuilds the state from the topic.
    pub anti_entropy: AntiEntropySettings,
    /// The chunk size and the rate cap of the bulk operation runner.
    pub bulk: BulkSettings,
    /// `ROUTE_CONFIGURATION_MAX_ROUTES`: the most routes one route configuration of a host may
    /// hold, 1 to 1,000.
    pub route_configuration_max_routes: usize,
    /// `IAM_NAMESPACE`: the namespace IAM runs in; an upstream that targets
    /// it is refused with 422. None refuses only the system namespaces.
    pub iam_namespace: Option<String>,
    /// `LOKI_QUERY_URL`, `LOKI_TENANT_ID`, `ACCESS_LOG_QUERY_MAX_RANGE` and
    /// `ACCESS_LOG_QUERY_TIMEOUT`: how access decisions are read from Loki and what bounds a
    /// query (Story 14.3).
    pub access_log_query: AccessLogQuerySettings,
}

/// The settings of the bulk operation runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BulkSettings {
    /// `BULK_CHUNK_ENTITIES`: the most entities one version of a bulk change may change.
    pub chunker: BulkChunker,
    /// `BULK_MAX_RECORDS_PER_SECOND`: the most records per second the runner commits.
    pub pacing: BulkPacing,
}

/// The settings of the outbox relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySettings {
    /// `DATABASE_LISTEN_URL`: the direct connection of `LISTEN iam_outbox`; `DATABASE_URL` when
    /// the variable is not set.
    pub listen_url: String,
    /// `KAFKA_TRANSACTION_TIMEOUT`: `transaction.timeout.ms` of the relay producer, 1s to 10s.
    pub transaction_timeout: Duration,
    /// `PUBLISH_WAIT_TIMEOUT`: how long a write waits for the Kafka acknowledgement of its policy
    /// version, 100ms to 30s.
    pub publish_wait_timeout: Duration,
}

/// The settings of the offline validation of User service access tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenSettings {
    /// `JWT_PUBLIC_KEYS_FILE`: 1 to 3 PEM RSA public keys, checked when the configuration is read.
    pub public_keys_file: PathBuf,
    /// Issuer, audience, `MAX_TOKEN_LIFETIME` and `JWT_CLOCK_SKEW`.
    pub jwt: JwtSettings,
    /// `TOKEN_MEMO_CAPACITY` and `TOKEN_MEMO_MAX_TTL`.
    pub memo: TokenMemoSettings,
    /// `JWT_CALLER_AUDIENCE` and `JWT_SERVICE_TOKEN_MAX_LIFETIME`: what a service caller's token
    /// must satisfy to call IAM's own API.
    pub callers: CallerTokenRule,
}

impl Config {
    /// Parses and validates every setting, including the rules between settings.
    ///
    /// # Errors
    ///
    /// Returns every problem found, each naming its environment variable.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the arguments are handed over to the configuration (AD-07)"
    )]
    pub fn from_args(args: ServeArgs) -> Result<Self, ConfigErrors> {
        let mut collector = Collector::default();
        let server = server(&mut collector, &args);
        let database = database(&mut collector, &args.database);
        let sqs = sqs(&mut collector, &args);
        let limits = limits(&mut collector, &args);
        let iam_namespace = iam_namespace(&mut collector, &args);
        let tokens = tokens(&mut collector, &args.tokens);
        let app_env = server.as_ref().map(|server| server.app_env);
        let kafka = kafka(&mut collector, &args.kafka, app_env);
        let access_log_query = access_log_query_settings(&mut collector, &args, app_env);
        collector.cross_field_rules(database.as_ref(), sqs.as_ref(), limits.as_ref());
        let tasks = task_settings(
            &mut collector,
            &args,
            database.as_ref().map(|settings| settings.url.as_str()),
        );
        match (
            (server, database, sqs, limits),
            (tokens, kafka, tasks, access_log_query),
        ) {
            (
                (Some(server), Some(database), Some(sqs), Some(limits)),
                (Some(tokens), Some(kafka), Some(tasks), Some(access_log_query)),
            ) if collector.problems.is_empty() => Ok(Self {
                app_env: server.app_env,
                host: server.host,
                port: server.port,
                log_level: server.log_level,
                database,
                sqs,
                health_probe_timeout: limits.health_probe_timeout,
                request_timeout: limits.request_timeout,
                max_body_bytes: limits.max_body_bytes,
                shutdown_grace_period: limits.shutdown_grace_period,
                tokens,
                kafka,
                maintenance: tasks.0,
                relay: tasks.1,
                anti_entropy: tasks.2,
                bulk: tasks.3,
                route_configuration_max_routes: limits.route_configuration_max_routes,
                iam_namespace,
                access_log_query,
            }),
            _ => Err(ConfigErrors(collector.problems)),
        }
    }
}

/// The settings of `migrate` and `migrate revert`: the database and how long to wait for it.
#[derive(Debug, Clone)]
pub struct MigrateSettings {
    /// The PostgreSQL pool.
    pub database: PostgresSettings,
    /// How long to wait for the database, one attempt per second.
    pub wait_timeout: Duration,
}

impl MigrateSettings {
    /// Parses and validates the database variables and `DATABASE_WAIT_TIMEOUT`.
    ///
    /// # Errors
    ///
    /// Returns every problem found, each naming its environment variable.
    pub fn from_args(args: &MigrateArgs) -> Result<Self, ConfigErrors> {
        let mut collector = Collector::default();
        let database = database(&mut collector, &args.database);
        let wait = collector.collect(
            "DATABASE_WAIT_TIMEOUT",
            duration(args.wait_timeout.as_deref(), Duration::from_secs(30)),
        );
        match (database, wait) {
            (Some(database), Some(wait_timeout)) => Ok(Self {
                database,
                wait_timeout,
            }),
            _ => Err(ConfigErrors(collector.problems)),
        }
    }
}

/// The certificate chain and the private key of the public listener of the gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFiles {
    /// `GATEWAY_TLS_CERT_FILE`: the PEM certificate chain.
    pub cert: PathBuf,
    /// `GATEWAY_TLS_KEY_FILE`: the PEM private key.
    pub key: PathBuf,
}

/// The validated configuration of `gateway` and of `check-config --mode gateway`: no database or
/// queue setting; the Kafka settings are those of the bootstrap connection of the pod.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// Deployment environment.
    pub app_env: AppEnv,
    /// `tracing` filter directives.
    pub log_level: String,
    /// Time the in-flight requests get to finish after a termination signal.
    pub shutdown_grace_period: Duration,
    /// Offline validation of User service access tokens.
    pub tokens: TokenSettings,
    /// `GATEWAY_LISTEN`: the public listener.
    pub listen: SocketAddr,
    /// `GATEWAY_INTERNAL_LISTEN`: the internal listener.
    pub internal_listen: SocketAddr,
    /// `GATEWAY_PROBE_LISTEN`: the probe listener.
    pub probe_listen: SocketAddr,
    /// `GATEWAY_DECISION_LISTEN`: the decision listener, which serves the decision API from the
    /// snapshot and nothing else.
    pub decision_listen: SocketAddr,
    /// The certificate and key of the public listener; `None` serves plain HTTP, which only
    /// `APP_ENV` `dev` and `test` accept.
    pub tls: Option<TlsFiles>,
    /// `POD_NAME`: the name of the pod, when the downward API provides it.
    pub pod_name: Option<String>,
    /// `POD_NAMESPACE`: the namespace of the pod, when the downward API provides it.
    pub pod_namespace: Option<String>,
    /// How the endpoints of the upstreams are discovered and preferred by zone.
    pub endpoints: EndpointSettings,
    /// The state topic and the connection that reads it, under the principal
    /// `iam-gateway-bootstrap` (`KAFKA_BOOTSTRAP_SASL_USERNAME`, `KAFKA_BOOTSTRAP_SASL_PASSWORD`).
    pub kafka: KafkaSettings,
    /// The connection of the tail: the principal `iam-gateway` (`KAFKA_SASL_USERNAME`,
    /// `KAFKA_SASL_PASSWORD`) with the client id `iam-gateway-<pod-name>`.
    pub kafka_tail: KafkaSettings,
    /// `KAFKA_FETCH_MAX_WAIT`: how long one fetch of the tail waits for records.
    pub kafka_fetch_max_wait: Duration,
    /// `FRESHNESS_READY_BOUND`: the longest random delay of a rebootstrap after a fence.
    pub freshness_ready_bound: Duration,
    /// `FRESHNESS_HARD_BOUND`: the longest a fenced pod keeps serving its last verified snapshot.
    pub freshness_hard_bound: Duration,
    /// `FRESHNESS_PROBE_INTERVAL`: how often the pod probes the state topic for a proof of
    /// freshness.
    pub freshness_probe_interval: Duration,
    /// `DERIVED_STATE_CHECK_INTERVAL`: how often a sixteenth of the shards is checked against the
    /// raw records.
    pub derived_state_check_interval: Duration,
    /// `READINESS_AZ_FLOOR`: how many ready pods of a zone never go unready for staleness.
    pub readiness_az_floor: usize,
    /// `LOG_ALLOW_SAMPLE_RATE`, `LOG_CLASS_BUDGETS` and `LOG_CHANNEL_CAPACITY`: what bounds the
    /// access log.
    pub access_log: AccessLogSettings,
    /// `LOKI_PUSH_URL`, `LOKI_TENANT_ID`, `ACCESS_LOG_AUDIT_FLUSH_INTERVAL` and
    /// `ACCESS_LOG_AUDIT_MAX_PENDING`: where the audit lane goes and when it stops admitting
    /// audited requests (Story 14.2).
    pub audit_lane: AuditLaneSettings,
    /// The shared rate counters: `RATE_LIMIT_STORE_URL`, `RATE_LIMIT_STORE_TIMEOUT` and
    /// `RATE_LIMIT_BREAKER_OPEN_DURATION`.
    pub rate_limit: RateLimitSettings,
    /// `RYW_MAX_WAIT`: the longest a request waits for a snapshot of the policy version it names
    /// (Story 10.10).
    pub ryw_max_wait: Duration,
}

/// How the gateway discovers the endpoints of its upstreams (`UPSTREAM_DISCOVERY`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamDiscovery {
    /// Watch the `EndpointSlices` of the Services through the Kubernetes API (the default).
    Kubernetes,
    /// Read the endpoints from this file (`UPSTREAM_STATIC_ENDPOINTS_FILE`), for compose and e2e.
    Static(PathBuf),
}

/// The endpoint discovery settings of the gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSettings {
    /// `UPSTREAM_DISCOVERY` with its file.
    pub discovery: UpstreamDiscovery,
    /// `UPSTREAM_ZONE_AWARE`: whether requests prefer the endpoints of the gateway's own zone.
    pub zone_aware: bool,
    /// `GATEWAY_ZONE`: the zone of the pod, which wins over the pod's entry in the peers slices.
    pub zone: Option<Zone>,
}

impl GatewayConfig {
    /// Parses and validates the gateway variables and the variables of `serve` that it shares.
    ///
    /// # Errors
    ///
    /// Returns every problem found, each naming its environment variable.
    pub fn from_args(args: &GatewayArgs) -> Result<Self, ConfigErrors> {
        let mut collector = Collector::default();
        let service = &args.service;
        let app_env = collector.collect("APP_ENV", app_env(service.app_env.as_deref()));
        let log_level = collector.collect("LOG_LEVEL", log_level(service.log_level.as_deref()));
        let grace = grace_period(&mut collector, service.shutdown_grace_period.as_deref());
        let tokens = tokens(&mut collector, &service.tokens);
        let listeners = listeners(&mut collector, args);
        let tls = tls_files(&mut collector, args, app_env);
        let (pod_name, pod_namespace) = pod_identity(&mut collector, args);
        let endpoints = endpoint_settings(&mut collector, args);
        let kafka = gateway_kafka(&mut collector, args, app_env);
        let tail = tail_settings(&mut collector, args);
        let (access_log, rate_limit, audit_lane) = lane_bounds(&mut collector, args, app_env);
        match (
            (app_env, log_level, grace, tokens),
            (listeners, tls, endpoints, kafka),
            (tail, rate_limit, audit_lane),
        ) {
            (
                (Some(app_env), Some(log_level), Some(shutdown_grace_period), Some(tokens)),
                (Some(listeners), Some(tls), Some(endpoints), Some(kafka)),
                (Some(tail), Some(rate_limit), Some(audit_lane)),
            ) if collector.problems.is_empty() => Ok(Self {
                app_env,
                log_level,
                shutdown_grace_period,
                tokens,
                listen: listeners.public,
                internal_listen: listeners.internal,
                probe_listen: listeners.probe,
                decision_listen: listeners.decision,
                tls: tls.into_files(),
                kafka_tail: tail_connection(kafka.tail, pod_name.as_deref()),
                kafka: kafka.bootstrap,
                kafka_fetch_max_wait: tail.fetch_max_wait,
                freshness_ready_bound: tail.ready_bound,
                freshness_hard_bound: tail.hard_bound,
                freshness_probe_interval: tail.probe_interval,
                derived_state_check_interval: tail.derived_check_interval,
                readiness_az_floor: tail.az_floor,
                access_log: access_log.unwrap_or_default(),
                audit_lane,
                rate_limit,
                ryw_max_wait: tail.ryw_max_wait,
                pod_name,
                pod_namespace,
                endpoints,
            }),
            _ => Err(ConfigErrors(collector.problems)),
        }
    }
}

/// The Kafka variables of the gateway: the control-plane connection variables, read twice. The
/// bootstrap read runs under the principal `iam-gateway-bootstrap`, whose
/// `KAFKA_BOOTSTRAP_SASL_USERNAME` and `KAFKA_BOOTSTRAP_SASL_PASSWORD` `SASL_SSL` requires; the tail
/// runs under the principal `iam-gateway`, whose `KAFKA_SASL_USERNAME` and `KAFKA_SASL_PASSWORD`
/// `SASL_SSL` requires as well. `KAFKA_CLIENT_ID` is not read: the client ids are the name of the
/// bootstrap principal and `iam-gateway-<pod-name>`.
fn gateway_kafka(
    collector: &mut Collector,
    args: &GatewayArgs,
    app_env: Option<AppEnv>,
) -> Option<GatewayKafka> {
    let mut forwarded = args.service.kafka.clone();
    forwarded.client_id = None;
    let principal = if matches!(
        security_protocol(forwarded.security_protocol.as_deref()),
        Ok(Protocol::SaslSsl)
    ) {
        bootstrap_principal(collector, args)
    } else {
        (String::new(), KafkaSecret::new(String::new()))
    };
    let tail = kafka(collector, &forwarded, app_env)?;
    let bootstrap = tail.bootstrap_principal(principal.0, principal.1);
    Some(GatewayKafka { bootstrap, tail })
}

/// The two Kafka connections of a gateway pod: the bootstrap read and the tail.
struct GatewayKafka {
    /// Under the principal `iam-gateway-bootstrap`.
    bootstrap: KafkaSettings,
    /// Under the principal `iam-gateway` (`KAFKA_SASL_USERNAME`, `KAFKA_SASL_PASSWORD`); the client
    /// id is set from the pod name.
    tail: KafkaSettings,
}

/// The client id of the tail connection: `iam-gateway-<pod-name>`.
/// `POD_NAME` and `POD_NAMESPACE`, each absent when the downward API does not provide it.
fn pod_identity(collector: &mut Collector, args: &GatewayArgs) -> (Option<String>, Option<String>) {
    let pod_name = collector.collect("POD_NAME", optional(args.pod_name.as_deref()));
    let pod_namespace = collector.collect("POD_NAMESPACE", optional(args.pod_namespace.as_deref()));
    (pod_name.flatten(), pod_namespace.flatten())
}

/// The tail connection with the client id `iam-gateway-<pod-name>`.
fn tail_connection(tail: KafkaSettings, pod_name: Option<&str>) -> KafkaSettings {
    KafkaSettings {
        client_id: tail_client_id(pod_name),
        ..tail
    }
}

fn tail_client_id(pod_name: Option<&str>) -> String {
    format!("iam-gateway-{}", pod_name.unwrap_or("unknown"))
}

/// The settings of the tail and of the freshness bounds.
struct TailSettings {
    fetch_max_wait: Duration,
    ready_bound: Duration,
    hard_bound: Duration,
    probe_interval: Duration,
    derived_check_interval: Duration,
    az_floor: usize,
    ryw_max_wait: Duration,
}

/// `KAFKA_FETCH_MAX_WAIT` (100ms), `FRESHNESS_READY_BOUND` (2s), `FRESHNESS_HARD_BOUND` (15s) and
/// `FRESHNESS_PROBE_INTERVAL` (500ms), `DERIVED_STATE_CHECK_INTERVAL` (1s) and `READINESS_AZ_FLOOR`
/// (1, from 1 to 8): the hard bound lies from 3s to 30s and above the ready bound.
fn tail_settings(collector: &mut Collector, args: &GatewayArgs) -> Option<TailSettings> {
    let fetch_max_wait = collector.collect(
        "KAFKA_FETCH_MAX_WAIT",
        positive_duration(
            args.kafka_fetch_max_wait.as_deref(),
            Duration::from_millis(100),
        ),
    );
    let ready_bound = collector.collect(
        "FRESHNESS_READY_BOUND",
        positive_duration(
            args.freshness_ready_bound.as_deref(),
            Duration::from_secs(2),
        ),
    );
    let hard_bound = hard_bound_over(collector, args, ready_bound);
    let derived_check_interval = collector.collect(
        "DERIVED_STATE_CHECK_INTERVAL",
        positive_duration(
            args.derived_state_check_interval.as_deref(),
            Duration::from_secs(1),
        ),
    );
    let probe_interval = collector.collect(
        "FRESHNESS_PROBE_INTERVAL",
        positive_duration(
            args.freshness_probe_interval.as_deref(),
            Duration::from_millis(500),
        ),
    );
    let az_floor = collector.collect(
        "READINESS_AZ_FLOOR",
        bounded(
            args.readiness_az_floor.as_deref(),
            1_usize,
            1..=MAX_AZ_FLOOR,
        ),
    );
    let ryw_max_wait = collector.collect(
        "RYW_MAX_WAIT",
        positive_duration(args.ryw_max_wait.as_deref(), Duration::from_secs(1)),
    );
    Some(TailSettings {
        ryw_max_wait: ryw_max_wait?,
        fetch_max_wait: fetch_max_wait?,
        ready_bound: ready_bound?,
        hard_bound: hard_bound?,
        probe_interval: probe_interval?,
        derived_check_interval: derived_check_interval?,
        az_floor: az_floor?,
    })
}

/// What bounds the access log of the gateway (FR-50, FR-55).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessLogSettings {
    /// `LOG_ALLOW_SAMPLE_RATE`: the share of ordinary allows that is written.
    pub allow_sample_rate: SampleRate,
    /// `LOG_CLASS_BUDGETS`: the records per second of the `error` and `audit` classes.
    pub class_budgets: ClassBudgets,
    /// `LOG_CHANNEL_CAPACITY`: the capacity of the channel to the writer.
    pub channel_capacity: usize,
}

impl Default for AccessLogSettings {
    fn default() -> Self {
        Self {
            allow_sample_rate: default_sample_rate(),
            class_budgets: ClassBudgets::default(),
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
        }
    }
}

/// The sample rate of a configuration that does not set `LOG_ALLOW_SAMPLE_RATE`: 0.01.
fn default_sample_rate() -> SampleRate {
    SampleRate::parse("0.01").unwrap_or(SampleRate::NONE)
}

/// `LOG_ALLOW_SAMPLE_RATE` (0 to 1, default 0.01), `LOG_CLASS_BUDGETS` (default
/// `error=1000,audit=2000`) and `LOG_CHANNEL_CAPACITY` (1 to 16777216, default 65536).
///
/// `None` when a problem was reported.
fn access_log_settings(collector: &mut Collector, args: &GatewayArgs) -> Option<AccessLogSettings> {
    let rate = collector.collect(
        "LOG_ALLOW_SAMPLE_RATE",
        access_log_value(
            args.log_allow_sample_rate.as_deref(),
            default_sample_rate(),
            SampleRate::parse,
        ),
    );
    let budgets = collector.collect(
        "LOG_CLASS_BUDGETS",
        access_log_value(
            args.log_class_budgets.as_deref(),
            ClassBudgets::default(),
            ClassBudgets::parse,
        ),
    );
    let capacity = collector.collect(
        "LOG_CHANNEL_CAPACITY",
        access_log_value(
            args.log_channel_capacity.as_deref(),
            DEFAULT_CHANNEL_CAPACITY,
            parse_channel_capacity,
        ),
    );
    Some(AccessLogSettings {
        allow_sample_rate: rate?,
        class_budgets: budgets?,
        channel_capacity: capacity?,
    })
}

/// An access log value: `default` when the variable is not set, otherwise what `parse` reads,
/// with the reason of its refusal.
fn access_log_value<T>(
    raw: Option<&str>,
    default: T,
    parse: fn(&str) -> Result<T, InvalidAccessLogSetting>,
) -> Parsed<T> {
    raw.map_or(Ok(default), |value| {
        parse(value).map_err(|error| error.to_string())
    })
}

/// The largest accepted `READINESS_AZ_FLOOR`.
const MAX_AZ_FLOOR: usize = 8;

/// The shared rate counters of the gateway (Story 12.2, FR-65).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitSettings {
    /// `RATE_LIMIT_STORE_URL`: the Valkey server, or the Sentinel group that names its master.
    pub store: ValkeyEndpoint,
    /// `RATE_LIMIT_STORE_TIMEOUT`: the longest one call of the shared store may take.
    pub store_timeout: Duration,
    /// `RATE_LIMIT_BREAKER_OPEN_DURATION`: how long the breaker of the store stays open before one
    /// probe call (Story 12.3).
    pub breaker_open_duration: Duration,
}

/// The URL of the local Valkey when `RATE_LIMIT_STORE_URL` is unset.
pub const DEFAULT_RATE_LIMIT_STORE_URL: &str = "redis://localhost:6379";

/// The shortest accepted `RATE_LIMIT_STORE_TIMEOUT`.
const MIN_RATE_LIMIT_STORE_TIMEOUT: Duration = Duration::from_millis(1);

/// The longest accepted `RATE_LIMIT_STORE_TIMEOUT`.
const MAX_RATE_LIMIT_STORE_TIMEOUT: Duration = Duration::from_millis(50);

/// The shortest accepted `RATE_LIMIT_BREAKER_OPEN_DURATION`.
const MIN_RATE_LIMIT_BREAKER_OPEN_DURATION: Duration = Duration::from_secs(1);

/// The longest accepted `RATE_LIMIT_BREAKER_OPEN_DURATION`.
const MAX_RATE_LIMIT_BREAKER_OPEN_DURATION: Duration = Duration::from_secs(300);

/// `RATE_LIMIT_STORE_URL` (`redis://` or `redis+sentinel://`, default the local Valkey),
/// `RATE_LIMIT_STORE_TIMEOUT` (1ms to 50ms, default 10ms) and `RATE_LIMIT_BREAKER_OPEN_DURATION`
/// (1s to 5m, default 5s).
///
/// `None` when a problem was reported.
fn rate_limit_settings(collector: &mut Collector, args: &GatewayArgs) -> Option<RateLimitSettings> {
    let store = collector.collect(
        "RATE_LIMIT_STORE_URL",
        rate_limit_store(args.rate_limit_store_url.as_deref()),
    );
    let timeout = collector.collect(
        "RATE_LIMIT_STORE_TIMEOUT",
        rate_limit_store_timeout(args.rate_limit_store_timeout.as_deref()),
    );
    let breaker = collector.collect(
        "RATE_LIMIT_BREAKER_OPEN_DURATION",
        rate_limit_breaker_open_duration(args.rate_limit_breaker_open_duration.as_deref()),
    );
    Some(RateLimitSettings {
        store: store?,
        store_timeout: timeout?,
        breaker_open_duration: breaker?,
    })
}

fn rate_limit_store(raw: Option<&str>) -> Parsed<ValkeyEndpoint> {
    ValkeyEndpoint::parse(raw.unwrap_or(DEFAULT_RATE_LIMIT_STORE_URL))
        .map_err(|error| format!("must be a redis:// or redis+sentinel:// URL: {error}"))
}

fn rate_limit_store_timeout(raw: Option<&str>) -> Parsed<Duration> {
    let value = duration(raw, Duration::from_millis(10))?;
    if (MIN_RATE_LIMIT_STORE_TIMEOUT..=MAX_RATE_LIMIT_STORE_TIMEOUT).contains(&value) {
        Ok(value)
    } else {
        Err("must be a duration from 1ms to 50ms".to_owned())
    }
}

fn rate_limit_breaker_open_duration(raw: Option<&str>) -> Parsed<Duration> {
    let value = duration(raw, Duration::from_secs(5))?;
    if (MIN_RATE_LIMIT_BREAKER_OPEN_DURATION..=MAX_RATE_LIMIT_BREAKER_OPEN_DURATION)
        .contains(&value)
    {
        Ok(value)
    } else {
        Err("must be a duration from 1s to 5m".to_owned())
    }
}

/// `SHUTDOWN_GRACE_PERIOD`: how long in-flight requests get to finish (default `10s`).
fn grace_period(collector: &mut Collector, raw: Option<&str>) -> Option<Duration> {
    collector.collect(
        "SHUTDOWN_GRACE_PERIOD",
        duration(raw, Duration::from_secs(10)),
    )
}

/// `FRESHNESS_HARD_BOUND`, which must be longer than `FRESHNESS_READY_BOUND`.
fn hard_bound_over(
    collector: &mut Collector,
    args: &GatewayArgs,
    ready_bound: Option<Duration>,
) -> Option<Duration> {
    let hard_bound = collector.collect(
        "FRESHNESS_HARD_BOUND",
        hard_bound_value(args.freshness_hard_bound.as_deref()),
    );
    collector.longer_than(
        "FRESHNESS_HARD_BOUND",
        hard_bound,
        "FRESHNESS_READY_BOUND",
        ready_bound,
    );
    hard_bound
}

/// The shortest accepted `FRESHNESS_HARD_BOUND`.
const MIN_HARD_BOUND: Duration = Duration::from_secs(3);

/// The longest accepted `FRESHNESS_HARD_BOUND`.
const MAX_HARD_BOUND: Duration = Duration::from_secs(30);

/// `FRESHNESS_HARD_BOUND`: from 3 to 30 seconds, 15 by default.
fn hard_bound_value(raw: Option<&str>) -> Parsed<Duration> {
    let value = duration(raw, Duration::from_secs(15))?;
    if (MIN_HARD_BOUND..=MAX_HARD_BOUND).contains(&value) {
        Ok(value)
    } else {
        Err("must be a duration from 3s to 30s".to_owned())
    }
}

/// `KAFKA_BOOTSTRAP_SASL_USERNAME` and `KAFKA_BOOTSTRAP_SASL_PASSWORD`: both required.
fn bootstrap_principal(collector: &mut Collector, args: &GatewayArgs) -> (String, KafkaSecret) {
    let username = collector.collect(
        "KAFKA_BOOTSTRAP_SASL_USERNAME",
        required(args.kafka_bootstrap_sasl_username.as_deref()),
    );
    let password = collector.collect(
        "KAFKA_BOOTSTRAP_SASL_PASSWORD",
        required(args.kafka_bootstrap_sasl_password.as_deref()),
    );
    (
        username.unwrap_or_default(),
        KafkaSecret::new(password.unwrap_or_default()),
    )
}

/// `UPSTREAM_DISCOVERY`, `UPSTREAM_STATIC_ENDPOINTS_FILE`, `UPSTREAM_ZONE_AWARE` and
/// `GATEWAY_ZONE`. The file is read and parsed now, so that `check-config` refuses a gateway that
/// would start without endpoints.
///
/// `None` when a problem was reported.
fn endpoint_settings(collector: &mut Collector, args: &GatewayArgs) -> Option<EndpointSettings> {
    let mode = collector.collect(
        "UPSTREAM_DISCOVERY",
        discovery_is_static(args.upstream_discovery.as_deref()),
    );
    let file = collector.collect(
        "UPSTREAM_STATIC_ENDPOINTS_FILE",
        optional(args.upstream_static_endpoints_file.as_deref()),
    );
    let zone_aware = collector.collect(
        "UPSTREAM_ZONE_AWARE",
        parsed(
            args.upstream_zone_aware.as_deref(),
            true,
            "must be true or false",
        ),
    );
    let zone = collector.collect("GATEWAY_ZONE", gateway_zone(args.gateway_zone.as_deref()));
    let discovery = if mode? {
        static_discovery(collector, file?)
    } else {
        Some(UpstreamDiscovery::Kubernetes)
    };
    Some(EndpointSettings {
        discovery: discovery?,
        zone_aware: zone_aware?,
        zone: zone?,
    })
}

/// Whether `UPSTREAM_DISCOVERY` selects the static file: `static` does, `kubernetes` (the default)
/// does not.
fn discovery_is_static(raw: Option<&str>) -> Parsed<bool> {
    match raw {
        None | Some("kubernetes") => Ok(false),
        Some("static") => Ok(true),
        Some(_) => Err("must be one of kubernetes, static".to_owned()),
    }
}

fn gateway_zone(raw: Option<&str>) -> Parsed<Option<Zone>> {
    optional(raw)?
        .map(|zone| {
            Zone::new(&zone)
                .map_err(|_invalid| "must be 1 to 63 letters, digits, '-', '_' or '.'".to_owned())
        })
        .transpose()
}

/// The static discovery: the file must be named and must hold valid endpoints.
fn static_discovery(collector: &mut Collector, file: Option<String>) -> Option<UpstreamDiscovery> {
    let Some(path) = file else {
        return collector.reject(
            "UPSTREAM_STATIC_ENDPOINTS_FILE",
            "is required when UPSTREAM_DISCOVERY is static",
        );
    };
    match StaticEndpointWatch::new(std::path::Path::new(&path)) {
        Ok(_watch) => Some(UpstreamDiscovery::Static(PathBuf::from(path))),
        Err(error) => collector.reject(
            "UPSTREAM_STATIC_ENDPOINTS_FILE",
            &format!("must name a readable JSON file of upstream endpoints: {error}"),
        ),
    }
}

/// The four listener addresses of the gateway.
struct Listeners {
    public: SocketAddr,
    internal: SocketAddr,
    probe: SocketAddr,
    decision: SocketAddr,
}

/// `GATEWAY_LISTEN`, `GATEWAY_INTERNAL_LISTEN`, `GATEWAY_PROBE_LISTEN` and
/// `GATEWAY_DECISION_LISTEN`: four addresses that differ from one another (port 0, which selects
/// any free port, never clashes).
fn listeners(collector: &mut Collector, args: &GatewayArgs) -> Option<Listeners> {
    let public = collector.collect(
        "GATEWAY_LISTEN",
        listen_address(args.listen.as_deref(), 8443),
    );
    let internal = collector.collect(
        "GATEWAY_INTERNAL_LISTEN",
        listen_address(args.internal_listen.as_deref(), 9090),
    );
    let probe = collector.collect(
        "GATEWAY_PROBE_LISTEN",
        listen_address(args.probe_listen.as_deref(), 9092),
    );
    collector.distinct(
        ("GATEWAY_INTERNAL_LISTEN", internal),
        ("GATEWAY_LISTEN", public),
    );
    collector.distinct(("GATEWAY_PROBE_LISTEN", probe), ("GATEWAY_LISTEN", public));
    collector.distinct(
        ("GATEWAY_PROBE_LISTEN", probe),
        ("GATEWAY_INTERNAL_LISTEN", internal),
    );
    let decision = collector.collect(
        "GATEWAY_DECISION_LISTEN",
        listen_address(args.decision_listen.as_deref(), 9091),
    );
    collector.distinct(
        ("GATEWAY_DECISION_LISTEN", decision),
        ("GATEWAY_LISTEN", public),
    );
    collector.distinct(
        ("GATEWAY_DECISION_LISTEN", decision),
        ("GATEWAY_INTERNAL_LISTEN", internal),
    );
    collector.distinct(
        ("GATEWAY_DECISION_LISTEN", decision),
        ("GATEWAY_PROBE_LISTEN", probe),
    );
    Some(Listeners {
        public: public?,
        internal: internal?,
        probe: probe?,
        decision: decision?,
    })
}

fn listen_address(raw: Option<&str>, default_port: u16) -> Parsed<SocketAddr> {
    parsed(
        raw,
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, default_port)),
        "must be an address of the form host:port, such as 0.0.0.0:8443",
    )
}

/// `GATEWAY_TLS_CERT_FILE` and `GATEWAY_TLS_KEY_FILE`: both or neither; neither only in `dev`
/// and `test`; a pair must hold a usable certificate chain and its private key now, so that
/// `check-config` refuses a pair the gateway could not start with.
///
/// `None` when a problem was reported or the environment is unknown.
fn tls_files(
    collector: &mut Collector,
    args: &GatewayArgs,
    app_env: Option<AppEnv>,
) -> Option<TlsChoice> {
    match (args.tls_cert_file.as_deref(), args.tls_key_file.as_deref()) {
        (Some(cert), Some(key)) => tls_pair(collector, cert, key),
        (Some(_), None) => collector.reject(
            "GATEWAY_TLS_KEY_FILE",
            "is required with GATEWAY_TLS_CERT_FILE",
        ),
        (None, Some(_)) => collector.reject(
            "GATEWAY_TLS_CERT_FILE",
            "is required with GATEWAY_TLS_KEY_FILE",
        ),
        (None, None) => match app_env? {
            AppEnv::Dev | AppEnv::Test => Some(TlsChoice::Plain),
            AppEnv::Prod => {
                collector.reject::<()>("GATEWAY_TLS_CERT_FILE", TLS_REQUIRED);
                collector.reject("GATEWAY_TLS_KEY_FILE", TLS_REQUIRED)
            }
        },
    }
}

/// How the public listener of the gateway is served.
enum TlsChoice {
    /// Plain HTTP, accepted only in `dev` and `test`.
    Plain,
    /// TLS with this pair.
    Secured(TlsFiles),
}

impl TlsChoice {
    fn into_files(self) -> Option<TlsFiles> {
        match self {
            Self::Plain => None,
            Self::Secured(files) => Some(files),
        }
    }
}

/// The reason of a missing TLS file.
const TLS_REQUIRED: &str = "is required outside APP_ENV dev and test";

fn tls_pair(collector: &mut Collector, cert: &str, key: &str) -> Option<TlsChoice> {
    let files = TlsFiles {
        cert: PathBuf::from(cert),
        key: PathBuf::from(key),
    };
    match listener::load_certified_key(&files) {
        Ok(_loaded) => Some(TlsChoice::Secured(files)),
        Err(error) => collector.reject(
            "GATEWAY_TLS_CERT_FILE",
            &format!(
                "must name a PEM certificate chain that matches the private key of GATEWAY_TLS_KEY_FILE: {error}"
            ),
        ),
    }
}

struct Server {
    app_env: AppEnv,
    host: IpAddr,
    port: u16,
    log_level: String,
}

struct Limits {
    health_probe_timeout: Duration,
    request_timeout: Duration,
    max_body_bytes: usize,
    shutdown_grace_period: Duration,
    route_configuration_max_routes: usize,
}

type Parsed<T> = Result<T, String>;

/// Gathers the problems of all variables.
#[derive(Default)]
struct Collector {
    problems: Vec<ConfigProblem>,
}

impl Collector {
    fn collect<T>(&mut self, variable: &'static str, outcome: Parsed<T>) -> Option<T> {
        outcome
            .map_err(|reason| self.problems.push(ConfigProblem { variable, reason }))
            .ok()
    }

    /// Records a problem of `variable` and returns `None`, the outcome of a rejected setting.
    fn reject<T>(&mut self, variable: &'static str, reason: &str) -> Option<T> {
        self.problems.push(ConfigProblem {
            variable,
            reason: reason.to_owned(),
        });
        None
    }

    /// Records a problem of the first variable when both addresses are known, equal and not port 0.
    fn distinct(
        &mut self,
        (variable, address): (&'static str, Option<SocketAddr>),
        (other, other_address): (&'static str, Option<SocketAddr>),
    ) {
        if let (Some(address), Some(other_address)) = (address, other_address)
            && address == other_address
            && address.port() != 0
        {
            self.reject::<()>(variable, &format!("must differ from {other}"));
        }
    }

    fn credentials(&mut self, key_id: Option<&str>, secret: Option<&str>) {
        let problem = match (key_id.is_some(), secret.is_some()) {
            (true, false) => Some(("AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID")),
            (false, true) => Some(("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")),
            (true, true) | (false, false) => None,
        };
        if let Some((missing, present)) = problem {
            self.problems.push(ConfigProblem {
                variable: missing,
                reason: format!("is required when {present} is set"),
            });
        }
    }

    /// `KAFKA_PROBE_SASL_USERNAME` and `KAFKA_PROBE_SASL_PASSWORD`: both or neither. `None` when
    /// neither is set, and when a problem was reported (the configuration is refused then).
    fn probe_credentials(
        &mut self,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Option<ProbeCredentials> {
        let username = self.collect("KAFKA_PROBE_SASL_USERNAME", optional(username));
        let password = self.collect("KAFKA_PROBE_SASL_PASSWORD", optional(password));
        match (username?, password?) {
            (Some(username), Some(password)) => Some(ProbeCredentials {
                username,
                password: KafkaSecret::new(password),
            }),
            (None, None) => None,
            (Some(_), None) => self.reject(
                "KAFKA_PROBE_SASL_PASSWORD",
                "is required when KAFKA_PROBE_SASL_USERNAME is set",
            ),
            (None, Some(_)) => self.reject(
                "KAFKA_PROBE_SASL_USERNAME",
                "is required when KAFKA_PROBE_SASL_PASSWORD is set",
            ),
        }
    }

    /// `KAFKA_SECURITY_PROTOCOL=PLAINTEXT` and `KAFKA_CONFIG_GATES=relaxed` exist for the compose
    /// broker, so only `dev` and `test` may use them.
    fn kafka_environment_rules(
        &mut self,
        app_env: Option<AppEnv>,
        protocol: Option<Protocol>,
        gates: Option<ConfigGates>,
    ) {
        if app_env != Some(AppEnv::Prod) {
            return;
        }
        if protocol == Some(Protocol::Plaintext) {
            self.problems.push(ConfigProblem {
                variable: "KAFKA_SECURITY_PROTOCOL",
                reason: "must be SASL_SSL unless APP_ENV is dev or test".to_owned(),
            });
        }
        if gates == Some(ConfigGates::Relaxed) {
            self.problems.push(ConfigProblem {
                variable: "KAFKA_CONFIG_GATES",
                reason: "must be enforce unless APP_ENV is dev or test".to_owned(),
            });
        }
    }

    fn cross_field_rules(
        &mut self,
        database: Option<&PostgresSettings>,
        sqs: Option<&SqsSettings>,
        limits: Option<&Limits>,
    ) {
        let acquire = database.map(|settings| settings.acquire_timeout);
        let operation = sqs.map(|settings| settings.operation_timeout);
        let probe = limits.map(|limits| limits.health_probe_timeout);
        let request = limits.map(|limits| limits.request_timeout);
        self.at_least(
            "HEALTH_PROBE_TIMEOUT",
            probe,
            "DATABASE_ACQUIRE_TIMEOUT",
            acquire,
        );
        self.at_least(
            "HEALTH_PROBE_TIMEOUT",
            probe,
            "SQS_OPERATION_TIMEOUT",
            operation,
        );
        self.longer_than(
            "HTTP_REQUEST_TIMEOUT",
            request,
            "HEALTH_PROBE_TIMEOUT",
            probe,
        );
    }

    fn at_least(
        &mut self,
        variable: &'static str,
        value: Option<Duration>,
        other_name: &str,
        other: Option<Duration>,
    ) {
        if let (Some(value), Some(other)) = (value, other)
            && value < other
        {
            self.problems.push(ConfigProblem {
                variable,
                reason: format!("must not be shorter than {other_name}"),
            });
        }
    }

    fn longer_than(
        &mut self,
        variable: &'static str,
        value: Option<Duration>,
        other_name: &str,
        other: Option<Duration>,
    ) {
        if let (Some(value), Some(other)) = (value, other)
            && value <= other
        {
            self.problems.push(ConfigProblem {
                variable,
                reason: format!("must be longer than {other_name}"),
            });
        }
    }
}

fn server(collector: &mut Collector, args: &ServeArgs) -> Option<Server> {
    let app_env = collector.collect("APP_ENV", app_env(args.app_env.as_deref()));
    let host = collector.collect("APP_HOST", host(args.app_host.as_deref()));
    let port = collector.collect("APP_PORT", port(args.app_port.as_deref()));
    let log_level = collector.collect("LOG_LEVEL", log_level(args.log_level.as_deref()));
    Some(Server {
        app_env: app_env?,
        host: host?,
        port: port?,
        log_level: log_level?,
    })
}

fn database(collector: &mut Collector, args: &DatabaseArgs) -> Option<PostgresSettings> {
    let url = collector.collect("DATABASE_URL", database_url(args.url.as_deref()));
    let max_connections = collector.collect(
        "DATABASE_MAX_CONNECTIONS",
        bounded(args.max_connections.as_deref(), 10, 1..=100),
    );
    let acquire = collector.collect(
        "DATABASE_ACQUIRE_TIMEOUT",
        duration(args.acquire_timeout.as_deref(), Duration::from_secs(2)),
    );
    let statement = collector.collect(
        "DATABASE_STATEMENT_TIMEOUT",
        statement_timeout(args.statement_timeout.as_deref()),
    );
    Some(PostgresSettings {
        url: url?,
        max_connections: max_connections?,
        acquire_timeout: acquire?,
        statement_timeout: statement?,
    })
}

fn sqs(collector: &mut Collector, args: &ServeArgs) -> Option<SqsSettings> {
    let region = collector.collect("AWS_REGION", required(args.aws_region.as_deref()));
    let endpoint = collector.collect(
        "AWS_ENDPOINT_URL_SQS",
        endpoint(args.aws_endpoint_url_sqs.as_deref()),
    );
    collector.credentials(
        args.aws_access_key_id.as_deref(),
        args.aws_secret_access_key.as_deref(),
    );
    let connect = collector.collect(
        "SQS_CONNECT_TIMEOUT",
        duration(
            args.sqs_connect_timeout.as_deref(),
            Duration::from_millis(500),
        ),
    );
    let operation = collector.collect(
        "SQS_OPERATION_TIMEOUT",
        duration(
            args.sqs_operation_timeout.as_deref(),
            Duration::from_secs(2),
        ),
    );
    let attempts = collector.collect(
        "SQS_MAX_ATTEMPTS",
        bounded(args.sqs_max_attempts.as_deref(), 1, 1..=5),
    );
    Some(SqsSettings {
        region: region?,
        endpoint_url: endpoint?,
        connect_timeout: connect?,
        operation_timeout: operation?,
        max_attempts: attempts?,
    })
}

/// The default and the largest `ROUTE_CONFIGURATION_MAX_ROUTES`.
const DEFAULT_ROUTE_CONFIGURATION_MAX_ROUTES: usize = 1_000;

fn limits(collector: &mut Collector, args: &ServeArgs) -> Option<Limits> {
    let probe = collector.collect(
        "HEALTH_PROBE_TIMEOUT",
        duration(args.health_probe_timeout.as_deref(), Duration::from_secs(3)),
    );
    let request = collector.collect(
        "HTTP_REQUEST_TIMEOUT",
        duration(
            args.http_request_timeout.as_deref(),
            Duration::from_secs(10),
        ),
    );
    let body = collector.collect(
        "HTTP_MAX_BODY_BYTES",
        bounded(
            args.http_max_body_bytes.as_deref(),
            65_536,
            1_024..=10_485_760,
        ),
    );
    let grace = collector.collect(
        "SHUTDOWN_GRACE_PERIOD",
        duration(
            args.shutdown_grace_period.as_deref(),
            Duration::from_secs(10),
        ),
    );
    let max_routes = collector.collect(
        "ROUTE_CONFIGURATION_MAX_ROUTES",
        bounded(
            args.route_configuration.max_routes.as_deref(),
            DEFAULT_ROUTE_CONFIGURATION_MAX_ROUTES,
            1..=DEFAULT_ROUTE_CONFIGURATION_MAX_ROUTES,
        ),
    );
    Some(Limits {
        health_probe_timeout: probe?,
        request_timeout: request?,
        max_body_bytes: body?,
        shutdown_grace_period: grace?,
        route_configuration_max_routes: max_routes?,
    })
}

fn tokens(collector: &mut Collector, args: &TokenArgs) -> Option<TokenSettings> {
    let file = collector.collect(
        "JWT_PUBLIC_KEYS_FILE",
        key_file(args.public_keys_file.as_deref()),
    );
    let issuer = collector.collect(
        "JWT_ISSUER",
        non_empty(args.issuer.as_deref(), "vilnacrm-user-service"),
    );
    let audience = collector.collect(
        "JWT_AUDIENCE",
        non_empty(args.audience.as_deref(), "vilnacrm-api"),
    );
    let skew = collector.collect("JWT_CLOCK_SKEW", clock_skew(args.clock_skew.as_deref()));
    let lifetime = collector.collect(
        "MAX_TOKEN_LIFETIME",
        max_token_lifetime(args.max_token_lifetime.as_deref()),
    );
    let memo = token_memo(collector, args, lifetime);
    let callers = caller_token_rule(collector, args, lifetime);
    Some(TokenSettings {
        public_keys_file: file?,
        jwt: JwtSettings {
            issuer: issuer?,
            audience: audience?,
            lifetime: TokenLifetimeRule::new(lifetime?, skew?),
        },
        memo: memo?,
        callers: callers?,
    })
}

/// `JWT_CALLER_AUDIENCE` and `JWT_SERVICE_TOKEN_MAX_LIFETIME`, the second checked against
/// `lifetime`, the valid `MAX_TOKEN_LIFETIME` when there is one.
fn caller_token_rule(
    collector: &mut Collector,
    args: &TokenArgs,
    lifetime: Option<Duration>,
) -> Option<CallerTokenRule> {
    let audience = collector.collect(
        "JWT_CALLER_AUDIENCE",
        non_empty(args.caller_audience.as_deref(), "vilnacrm-iam"),
    );
    let max_lifetime = collector.collect(
        "JWT_SERVICE_TOKEN_MAX_LIFETIME",
        service_token_max_lifetime(args.service_token_max_lifetime.as_deref(), lifetime),
    );
    Some(CallerTokenRule::new(audience?, max_lifetime?))
}

/// `JWT_SERVICE_TOKEN_MAX_LIFETIME`: a duration of at least 1s, at most 3600s and at most
/// `MAX_TOKEN_LIFETIME`.
///
/// When it is not set, 900 seconds or `MAX_TOKEN_LIFETIME` when that is shorter.
fn service_token_max_lifetime(raw: Option<&str>, lifetime: Option<Duration>) -> Parsed<Duration> {
    let default = lifetime.map_or(DEFAULT_SERVICE_TOKEN_MAX_LIFETIME, |lifetime| {
        lifetime.min(DEFAULT_SERVICE_TOKEN_MAX_LIFETIME)
    });
    let value = duration(raw, default)?;
    let within_lifetime = lifetime.is_none_or(|lifetime| value <= lifetime);
    let bounded = (Duration::from_secs(1)..=MAX_SERVICE_TOKEN_LIFETIME).contains(&value);
    if bounded && within_lifetime {
        Ok(value)
    } else {
        Err(
            "must be a duration of at least 1s, at most 3600s and at most MAX_TOKEN_LIFETIME"
                .to_owned(),
        )
    }
}

/// `TOKEN_MEMO_CAPACITY` and `TOKEN_MEMO_MAX_TTL`, the second checked against `lifetime`, the
/// valid `MAX_TOKEN_LIFETIME` when there is one.
fn token_memo(
    collector: &mut Collector,
    args: &TokenArgs,
    lifetime: Option<Duration>,
) -> Option<TokenMemoSettings> {
    let capacity = collector.collect(
        "TOKEN_MEMO_CAPACITY",
        token_memo_capacity(args.memo_capacity.as_deref()),
    );
    let max_ttl = collector.collect(
        "TOKEN_MEMO_MAX_TTL",
        token_memo_max_ttl(args.memo_max_ttl.as_deref(), lifetime),
    );
    Some(TokenMemoSettings {
        capacity: capacity?,
        max_ttl: max_ttl?,
    })
}

/// `TOKEN_MEMO_CAPACITY`: an integer of at least 1000.
fn token_memo_capacity(raw: Option<&str>) -> Parsed<u64> {
    let reason = "must be an integer of at least 1000";
    let value = parsed(raw, 200_000, reason)?;
    if value >= MIN_TOKEN_MEMO_CAPACITY {
        Ok(value)
    } else {
        Err(reason.to_owned())
    }
}

/// `TOKEN_MEMO_MAX_TTL`: a duration of at most `MAX_TOKEN_LIFETIME`; when it is not set, 900
/// seconds or `MAX_TOKEN_LIFETIME` when that is shorter.
fn token_memo_max_ttl(raw: Option<&str>, lifetime: Option<Duration>) -> Parsed<Duration> {
    let default = lifetime.map_or(DEFAULT_TOKEN_MEMO_MAX_TTL, |lifetime| {
        lifetime.min(DEFAULT_TOKEN_MEMO_MAX_TTL)
    });
    let value = duration(raw, default)?;
    if lifetime.is_none_or(|lifetime| value <= lifetime) {
        Ok(value)
    } else {
        Err("must be a duration of at most MAX_TOKEN_LIFETIME".to_owned())
    }
}

/// `JWT_PUBLIC_KEYS_FILE`: the file must hold 1 to 3 parsable PEM RSA public keys now, so that
/// `check-config` refuses a key file the service could not start with.
fn key_file(raw: Option<&str>) -> Parsed<PathBuf> {
    let path = PathBuf::from(required(raw)?);
    match JwtKeySet::load(&path) {
        Ok(_keys) => Ok(path),
        Err(error) => Err(format!(
            "must name a file of 1 to 3 PEM RSA public keys: {error}"
        )),
    }
}

/// `JWT_CLOCK_SKEW`: a duration of at most 60 seconds.
fn clock_skew(raw: Option<&str>) -> Parsed<Duration> {
    let value = duration(raw, Duration::from_secs(30))?;
    if value <= MAX_CLOCK_SKEW {
        Ok(value)
    } else {
        Err("must be a duration of at most 60s".to_owned())
    }
}

/// `MAX_TOKEN_LIFETIME`: a duration of at least one second.
fn max_token_lifetime(raw: Option<&str>) -> Parsed<Duration> {
    let value = duration(raw, Duration::from_mins(15))?;
    if value >= Duration::from_secs(1) {
        Ok(value)
    } else {
        Err("must be a duration of at least 1s".to_owned())
    }
}

/// How the Kafka connection is secured, before the credentials are attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Plaintext,
    SaslSsl,
}

/// The control-plane Kafka variables: the connection, the topics and the rules that relate them to
/// `APP_ENV`.
fn kafka(
    collector: &mut Collector,
    args: &KafkaArgs,
    app_env: Option<AppEnv>,
) -> Option<KafkaSettings> {
    let servers = collector.collect(
        "KAFKA_BOOTSTRAP_SERVERS",
        bootstrap_servers(args.bootstrap_servers.as_deref()),
    );
    let protocol = collector.collect(
        "KAFKA_SECURITY_PROTOCOL",
        security_protocol(args.security_protocol.as_deref()),
    );
    let security = kafka_security(collector, args, protocol);
    let client_id = collector.collect(
        "KAFKA_CLIENT_ID",
        non_empty(args.client_id.as_deref(), "iam-control"),
    );
    let timeouts = kafka_timeouts(collector, args);
    let gates = collector.collect(
        "KAFKA_CONFIG_GATES",
        config_gates(args.config_gates.as_deref()),
    );
    let topics = kafka_topics(collector, args);
    collector.kafka_environment_rules(app_env, protocol, gates);
    let (policy_topic, events_topic) = topics?;
    let (connect_timeout, request_timeout, retry_delay) = timeouts?;
    Some(KafkaSettings {
        bootstrap_servers: servers?,
        security: security?,
        client_id: client_id?,
        connect_timeout,
        request_timeout,
        retry_delay,
        gates: gates?,
        policy_topic,
        events_topic,
    })
}

/// `KAFKA_SASL_MECHANISM`, `KAFKA_SASL_USERNAME`, `KAFKA_SASL_PASSWORD`, `KAFKA_CA_FILE` and the
/// optional `KAFKA_PROBE_SASL_USERNAME` and `KAFKA_PROBE_SASL_PASSWORD`, which only `SASL_SSL`
/// reads: a `PLAINTEXT` connection ignores them.
fn kafka_security(
    collector: &mut Collector,
    args: &KafkaArgs,
    protocol: Option<Protocol>,
) -> Option<KafkaSecurity> {
    match protocol? {
        Protocol::Plaintext => Some(KafkaSecurity::Plaintext),
        Protocol::SaslSsl => {
            let mechanism = collector.collect(
                "KAFKA_SASL_MECHANISM",
                sasl_mechanism(args.sasl_mechanism.as_deref()),
            );
            let username = collector.collect(
                "KAFKA_SASL_USERNAME",
                required(args.sasl_username.as_deref()),
            );
            let password = collector.collect(
                "KAFKA_SASL_PASSWORD",
                required(args.sasl_password.as_deref()),
            );
            let ca_file = collector.collect("KAFKA_CA_FILE", optional(args.ca_file.as_deref()));
            let probe = collector.probe_credentials(
                args.probe_sasl_username.as_deref(),
                args.probe_sasl_password.as_deref(),
            );
            Some(KafkaSecurity::SaslSsl {
                mechanism: mechanism?,
                username: username?,
                password: KafkaSecret::new(password?),
                ca_file: ca_file?,
                probe,
            })
        }
    }
}

/// `KAFKA_CONNECT_TIMEOUT`, `KAFKA_REQUEST_TIMEOUT` (not shorter than the first) and
/// `KAFKA_RETRY_DELAY`.
fn kafka_timeouts(
    collector: &mut Collector,
    args: &KafkaArgs,
) -> Option<(Duration, Duration, Duration)> {
    let connect = collector.collect(
        "KAFKA_CONNECT_TIMEOUT",
        duration(args.connect_timeout.as_deref(), Duration::from_secs(1)),
    );
    let request = collector.collect(
        "KAFKA_REQUEST_TIMEOUT",
        duration(args.request_timeout.as_deref(), Duration::from_secs(2)),
    );
    let retry = collector.collect(
        "KAFKA_RETRY_DELAY",
        duration(args.retry_delay.as_deref(), Duration::from_millis(100)),
    );
    collector.at_least(
        "KAFKA_REQUEST_TIMEOUT",
        request,
        "KAFKA_CONNECT_TIMEOUT",
        connect,
    );
    Some((connect?, request?, retry?))
}

/// `MAINTENANCE_INTERVAL` and `ORPHANED_GRANT_RETENTION`: two positive durations.
fn maintenance_settings(
    collector: &mut Collector,
    args: &MaintenanceArgs,
) -> Option<MaintenanceSettings> {
    let defaults = MaintenanceSettings::default();
    let interval = collector.collect(
        "MAINTENANCE_INTERVAL",
        positive_duration(args.interval.as_deref(), defaults.interval),
    );
    let retention = collector.collect(
        "ORPHANED_GRANT_RETENTION",
        positive_duration(
            args.orphaned_grant_retention.as_deref(),
            defaults.orphaned_grant_retention,
        ),
    );
    Some(MaintenanceSettings {
        interval: interval?,
        orphaned_grant_retention: retention?,
    })
}

/// The settings of the background tasks: the maintenance, the outbox relay and the anti-entropy
/// task.
fn task_settings(
    collector: &mut Collector,
    args: &ServeArgs,
    database_url_fallback: Option<&str>,
) -> Option<(
    MaintenanceSettings,
    RelaySettings,
    AntiEntropySettings,
    BulkSettings,
)> {
    let maintenance = maintenance_settings(collector, &args.maintenance);
    let relay = relay_settings(collector, &args.relay, database_url_fallback);
    let anti_entropy = anti_entropy_settings(collector, &args.anti_entropy);
    let bulk = bulk_settings(collector, &args.bulk);
    Some((maintenance?, relay?, anti_entropy?, bulk?))
}

/// `ANTI_ENTROPY_HEAD_INTERVAL` and `ANTI_ENTROPY_FULL_INTERVAL`: two positive durations, the full
/// interval at least as long as the head interval.
fn anti_entropy_settings(
    collector: &mut Collector,
    args: &AntiEntropyArgs,
) -> Option<AntiEntropySettings> {
    let defaults = AntiEntropySettings::default();
    let head = collector.collect(
        "ANTI_ENTROPY_HEAD_INTERVAL",
        positive_duration(args.head_interval.as_deref(), defaults.head_interval()),
    );
    let full = collector.collect(
        "ANTI_ENTROPY_FULL_INTERVAL",
        positive_duration(args.full_interval.as_deref(), defaults.full_interval()),
    );
    collector.at_least(
        "ANTI_ENTROPY_FULL_INTERVAL",
        full,
        "ANTI_ENTROPY_HEAD_INTERVAL",
        head,
    );
    AntiEntropySettings::new(head?, full?).ok()
}

/// The default `BULK_CHUNK_ENTITIES`.
const DEFAULT_BULK_CHUNK_ENTITIES: usize = 1_000;

/// The default `BULK_MAX_RECORDS_PER_SECOND`.
const DEFAULT_BULK_RECORDS_PER_SECOND: u64 = 2_000;

/// `BULK_CHUNK_ENTITIES` (1 to 1,000) and `BULK_MAX_RECORDS_PER_SECOND` (at least 1).
fn bulk_settings(collector: &mut Collector, args: &BulkArgs) -> Option<BulkSettings> {
    let chunker = collector.collect("BULK_CHUNK_ENTITIES", bulk_chunker(args));
    let pacing = collector.collect("BULK_MAX_RECORDS_PER_SECOND", bulk_pacing(args));
    Some(BulkSettings {
        chunker: chunker?,
        pacing: pacing?,
    })
}

/// `BULK_CHUNK_ENTITIES`: an integer from 1 to 1,000.
fn bulk_chunker(args: &BulkArgs) -> Parsed<BulkChunker> {
    let reason = "must be an integer from 1 to 1000";
    let value = parsed(
        args.chunk_entities.as_deref(),
        DEFAULT_BULK_CHUNK_ENTITIES,
        reason,
    )?;
    BulkChunker::new(value).map_err(|_error| reason.to_owned())
}

/// `BULK_MAX_RECORDS_PER_SECOND`: an integer of at least 1.
fn bulk_pacing(args: &BulkArgs) -> Parsed<BulkPacing> {
    let reason = "must be an integer of at least 1";
    let value = parsed(
        args.max_records_per_second.as_deref(),
        DEFAULT_BULK_RECORDS_PER_SECOND,
        reason,
    )?;
    BulkPacing::new(value).map_err(|_error| reason.to_owned())
}

/// `DATABASE_LISTEN_URL` (`DATABASE_URL` when it is not set), `KAFKA_TRANSACTION_TIMEOUT` and
/// `PUBLISH_WAIT_TIMEOUT`.
fn relay_settings(
    collector: &mut Collector,
    args: &RelayArgs,
    database_url_fallback: Option<&str>,
) -> Option<RelaySettings> {
    let listen_url = args.listen_url.as_deref().map_or_else(
        || database_url_fallback.map(str::to_owned),
        |raw| collector.collect("DATABASE_LISTEN_URL", database_url(Some(raw))),
    );
    let transaction_timeout = collector.collect(
        "KAFKA_TRANSACTION_TIMEOUT",
        transaction_timeout(args.transaction_timeout.as_deref()),
    );
    let publish_wait_timeout = collector.collect(
        "PUBLISH_WAIT_TIMEOUT",
        publish_wait_timeout(args.publish_wait_timeout.as_deref()),
    );
    Some(RelaySettings {
        listen_url: listen_url?,
        transaction_timeout: transaction_timeout?,
        publish_wait_timeout: publish_wait_timeout?,
    })
}

/// The shortest accepted `PUBLISH_WAIT_TIMEOUT`.
const MIN_PUBLISH_WAIT_TIMEOUT: Duration = Duration::from_millis(100);

/// The longest accepted `PUBLISH_WAIT_TIMEOUT`.
const MAX_PUBLISH_WAIT_TIMEOUT: Duration = Duration::from_secs(30);

/// `PUBLISH_WAIT_TIMEOUT`: from 100 milliseconds to 30 seconds, 5 seconds by default.
fn publish_wait_timeout(raw: Option<&str>) -> Parsed<Duration> {
    let value = duration(raw, Duration::from_secs(5))?;
    if (MIN_PUBLISH_WAIT_TIMEOUT..=MAX_PUBLISH_WAIT_TIMEOUT).contains(&value) {
        Ok(value)
    } else {
        Err("must be a duration from 100ms to 30s".to_owned())
    }
}

/// The shortest accepted `KAFKA_TRANSACTION_TIMEOUT`.
const MIN_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(1);

/// The longest accepted `KAFKA_TRANSACTION_TIMEOUT`.
const MAX_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(10);

/// `KAFKA_TRANSACTION_TIMEOUT`: from 1 to 10 seconds, 10 by default.
fn transaction_timeout(raw: Option<&str>) -> Parsed<Duration> {
    let value = duration(raw, MAX_TRANSACTION_TIMEOUT)?;
    if (MIN_TRANSACTION_TIMEOUT..=MAX_TRANSACTION_TIMEOUT).contains(&value) {
        Ok(value)
    } else {
        Err("must be a duration from 1s to 10s".to_owned())
    }
}

/// `POLICY_TOPIC` and `EVENTS_TOPIC`, which must name two different topics.
fn kafka_topics(collector: &mut Collector, args: &KafkaArgs) -> Option<(String, String)> {
    let policy = collector.collect(
        "POLICY_TOPIC",
        topic_name(args.policy_topic.as_deref(), "iam.policy.state.v1"),
    );
    let events = collector.collect(
        "EVENTS_TOPIC",
        topic_name(args.events_topic.as_deref(), "iam.events.v1"),
    );
    if policy.is_some() && policy == events {
        collector.problems.push(ConfigProblem {
            variable: "EVENTS_TOPIC",
            reason: "must differ from POLICY_TOPIC".to_owned(),
        });
    }
    Some((policy?, events?))
}

/// `KAFKA_SECURITY_PROTOCOL`: `SASL_SSL` or `PLAINTEXT`; `SASL_SSL` when it is not set.
fn security_protocol(raw: Option<&str>) -> Parsed<Protocol> {
    match raw {
        None | Some("SASL_SSL") => Ok(Protocol::SaslSsl),
        Some("PLAINTEXT") => Ok(Protocol::Plaintext),
        Some(_) => Err("must be one of SASL_SSL, PLAINTEXT".to_owned()),
    }
}

/// `KAFKA_SASL_MECHANISM`: `SCRAM-SHA-512` or `SCRAM-SHA-256`; `SCRAM-SHA-512` when it is not set.
fn sasl_mechanism(raw: Option<&str>) -> Parsed<SaslMechanism> {
    match raw {
        None | Some("SCRAM-SHA-512") => Ok(SaslMechanism::ScramSha512),
        Some("SCRAM-SHA-256") => Ok(SaslMechanism::ScramSha256),
        Some(_) => Err("must be one of SCRAM-SHA-512, SCRAM-SHA-256".to_owned()),
    }
}

/// `KAFKA_CONFIG_GATES`: `enforce` or `relaxed`; `enforce` when it is not set.
fn config_gates(raw: Option<&str>) -> Parsed<ConfigGates> {
    match raw {
        None | Some("enforce") => Ok(ConfigGates::Enforce),
        Some("relaxed") => Ok(ConfigGates::Relaxed),
        Some(_) => Err("must be one of enforce, relaxed".to_owned()),
    }
}

/// `KAFKA_BOOTSTRAP_SERVERS`: one or more comma-separated `host:port` pairs.
fn bootstrap_servers(raw: Option<&str>) -> Parsed<String> {
    let value = required(raw)?;
    if value.split(',').all(|pair| is_host_and_port(pair.trim())) {
        Ok(value)
    } else {
        Err("must be comma-separated host:port pairs".to_owned())
    }
}

/// Whether `pair` is a host without whitespace or slash, a colon and a port from 1 to 65535.
fn is_host_and_port(pair: &str) -> bool {
    pair.rsplit_once(':').is_some_and(|(host, port)| {
        !host.is_empty()
            && !host.contains(|character: char| character.is_whitespace() || character == '/')
            && port.parse::<u16>().is_ok_and(|port| port > 0)
    })
}

/// A Kafka topic name: 1 to 249 letters, digits, `.`, `_` and `-`, and not `.` or `..`.
fn topic_name(raw: Option<&str>, default: &str) -> Parsed<String> {
    let name = non_empty(raw, default)?;
    let valid_characters = name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'));
    if valid_characters && name.len() <= 249 && name != "." && name != ".." {
        Ok(name)
    } else {
        Err(
            "must be a Kafka topic name of at most 249 letters, digits, '.', '_' and '-'"
                .to_owned(),
        )
    }
}

/// `IAM_NAMESPACE`, absent when it is not set.
fn iam_namespace(collector: &mut Collector, args: &ServeArgs) -> Option<String> {
    collector
        .collect("IAM_NAMESPACE", optional(args.iam_namespace.as_deref()))
        .flatten()
}

/// An optional text setting that must not be empty when it is set.
fn optional(raw: Option<&str>) -> Parsed<Option<String>> {
    raw.map(|value| required(Some(value))).transpose()
}

fn non_empty(raw: Option<&str>, default: &str) -> Parsed<String> {
    raw.map_or_else(|| Ok(default.to_owned()), |value| required(Some(value)))
}

fn app_env(raw: Option<&str>) -> Parsed<AppEnv> {
    match raw {
        None | Some("prod") => Ok(AppEnv::Prod),
        Some("dev") => Ok(AppEnv::Dev),
        Some("test") => Ok(AppEnv::Test),
        Some(_) => Err("must be one of dev, test, prod".to_owned()),
    }
}

fn host(raw: Option<&str>) -> Parsed<IpAddr> {
    parsed(
        raw,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        "must be an IP address",
    )
}

fn port(raw: Option<&str>) -> Parsed<u16> {
    parsed(raw, 8081, "must be an integer from 0 to 65535")
}

fn log_level(raw: Option<&str>) -> Parsed<String> {
    let directives = raw.unwrap_or("info");
    EnvFilter::try_new(directives)
        .map(|_filter| directives.to_owned())
        .map_err(|_error| "must be valid tracing filter directives, for example info".to_owned())
}

fn database_url(raw: Option<&str>) -> Parsed<String> {
    let url = required(raw)?;
    let scheme_ok = url.starts_with("postgres://") || url.starts_with("postgresql://");
    if scheme_ok && PgConnectOptions::from_str(&url).is_ok() {
        Ok(url)
    } else {
        Err("must be a postgres:// or postgresql:// URL".to_owned())
    }
}

fn endpoint(raw: Option<&str>) -> Parsed<Option<String>> {
    let Some(url) = raw else {
        return Ok(None);
    };
    let is_http_url = Uri::from_str(url).is_ok_and(|uri| {
        matches!(uri.scheme_str(), Some("http" | "https"))
            && uri.authority().is_some_and(has_host_and_valid_port)
    });
    if is_http_url {
        Ok(Some(url.to_owned()))
    } else {
        Err("must be an http:// or https:// URL".to_owned())
    }
}

/// `http::Uri` checks the port only when it is read, so the authority (after the optional user
/// information) must be the host alone, or the host followed by `:` and a port from 0 to 65535.
fn has_host_and_valid_port(authority: &Authority) -> bool {
    let text = authority.as_str();
    let address = text.rsplit_once('@').map_or(text, |(_, after)| after);
    let host = authority.host();
    !host.is_empty() && address.strip_prefix(host).is_some_and(is_empty_or_port)
}

/// The text after the host: nothing, or `:` followed by ASCII digits only (no sign) that fit a
/// `u16`.
fn is_empty_or_port(rest: &str) -> bool {
    rest.is_empty()
        || rest.strip_prefix(':').is_some_and(|digits| {
            digits.bytes().all(|byte| byte.is_ascii_digit()) && digits.parse::<u16>().is_ok()
        })
}

fn required(raw: Option<&str>) -> Parsed<String> {
    match raw {
        None => Err("is required".to_owned()),
        Some(value) if value.trim().is_empty() => Err("must not be empty".to_owned()),
        Some(value) => Ok(value.to_owned()),
    }
}

fn duration(raw: Option<&str>, default: Duration) -> Parsed<Duration> {
    raw.map_or(Ok(default), |value| {
        humantime::parse_duration(value)
            .map_err(|_error| "must be a duration such as 500ms, 2s or 1m".to_owned())
    })
}

/// A duration that is longer than zero.
fn positive_duration(raw: Option<&str>, default: Duration) -> Parsed<Duration> {
    let value = duration(raw, default)?;
    if value.is_zero() {
        Err("must be a positive duration such as 10m or 90d".to_owned())
    } else {
        Ok(value)
    }
}

/// `DATABASE_STATEMENT_TIMEOUT`: PostgreSQL reads 0 as "no timeout" and refuses more than about
/// 24.8 days, so the value must lie between 1 millisecond and 24 days.
fn statement_timeout(raw: Option<&str>) -> Parsed<Duration> {
    let value = duration(raw, Duration::from_secs(5))?;
    if (MIN_STATEMENT_TIMEOUT..=MAX_STATEMENT_TIMEOUT).contains(&value) {
        Ok(value)
    } else {
        Err("must be a duration from 1ms to 24d".to_owned())
    }
}

fn parsed<T: FromStr>(raw: Option<&str>, default: T, reason: &str) -> Parsed<T> {
    raw.map_or(Ok(default), |value| {
        value.parse().map_err(|_error| reason.to_owned())
    })
}

fn bounded<T>(raw: Option<&str>, default: T, bounds: RangeInclusive<T>) -> Parsed<T>
where
    T: FromStr + PartialOrd + Display,
{
    let reason = format!(
        "must be an integer from {} to {}",
        bounds.start(),
        bounds.end()
    );
    let value = parsed(raw, default, &reason)?;
    if bounds.contains(&value) {
        Ok(value)
    } else {
        Err(reason)
    }
}

#[cfg(test)]
mod tests;
