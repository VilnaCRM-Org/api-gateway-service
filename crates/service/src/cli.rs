//! The command line of the service binary.
//!
//! Every setting is an `Option<String>` bound to its environment variable, so clap never rejects a
//! value: [`crate::config::Config::from_args`] parses and validates all of them and names the
//! variable of every problem. `--help` names each variable and never prints a value.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Service binary of the template: serves the API and runs the maintenance commands.
#[derive(Debug, Parser)]
#[command(name = "service", version, about)]
pub struct Cli {
    /// The command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// The commands of the binary.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Validate the configuration, start logging, serve until SIGTERM or SIGINT, then drain.
    Serve(ServeArgs),
    /// Wait for the database and apply the pending migrations, or revert the last one.
    Migrate(MigrateArgs),
    /// Validate the configuration of a run mode without opening a socket or contacting a dependency.
    CheckConfig(CheckConfigArgs),
    /// Run the data plane: the TLS public listener, the internal listener and the probe listener,
    /// until SIGTERM or SIGINT, then drain. It needs no database.
    Gateway(GatewayArgs),
    /// Write the REST API contract (YAML) to a file or to standard output.
    OpenapiExport(ExportArgs),
    /// Write the GraphQL schema (SDL) to a file or to standard output.
    GraphqlExport(ExportArgs),
    /// Ask a running service whether it is alive (on the loopback interface or the `APP_HOST` address).
    Healthcheck(HealthcheckArgs),
    /// Create the first IAM administrator: the system role `iam-platform-admin` and its global
    /// assignment to a user or a service principal.
    IamBootstrap(IamBootstrapArgs),
}

/// The run mode a command works on: the one image runs as `iam-control` or as the gateway.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    /// `service serve`: the control plane, with the database (the default).
    #[default]
    Control,
    /// `service gateway`: the data plane, without a database.
    Gateway,
}

/// What `service migrate` does besides applying the pending migrations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Subcommand)]
pub enum MigrateAction {
    /// Revert the most recently applied migration.
    Revert,
}

/// Settings of the PostgreSQL pool.
#[derive(Debug, Clone, Default, Args)]
pub struct DatabaseArgs {
    /// `postgres://` or `postgresql://` URL of the database (required).
    #[arg(long = "database-url", env = "DATABASE_URL", hide_env_values = true)]
    pub url: Option<String>,
    /// Upper bound of open connections, 1 to 100 (default 10).
    #[arg(
        long = "database-max-connections",
        env = "DATABASE_MAX_CONNECTIONS",
        hide_env_values = true
    )]
    pub max_connections: Option<String>,
    /// How long a caller waits for a free connection (default 2s).
    #[arg(
        long = "database-acquire-timeout",
        env = "DATABASE_ACQUIRE_TIMEOUT",
        hide_env_values = true
    )]
    pub acquire_timeout: Option<String>,
    /// `statement_timeout` of every connection (default 5s).
    #[arg(
        long = "database-statement-timeout",
        env = "DATABASE_STATEMENT_TIMEOUT",
        hide_env_values = true
    )]
    pub statement_timeout: Option<String>,
}

/// Settings of `serve` and `check-config`: every service variable.
#[derive(Debug, Clone, Default, Args)]
pub struct ServeArgs {
    /// Deployment environment: `dev`, `test` or `prod` (default `prod`).
    #[arg(long = "app-env", env = "APP_ENV", hide_env_values = true)]
    pub app_env: Option<String>,
    /// IP address to listen on (default `0.0.0.0`).
    #[arg(long = "app-host", env = "APP_HOST", hide_env_values = true)]
    pub app_host: Option<String>,
    /// TCP port to listen on, 0 to 65535; 0 selects any free port (default 8081).
    #[arg(long = "app-port", env = "APP_PORT", hide_env_values = true)]
    pub app_port: Option<String>,
    /// `tracing` filter directives of the log output (default `info`).
    #[arg(long = "log-level", env = "LOG_LEVEL", hide_env_values = true)]
    pub log_level: Option<String>,
    /// Settings of the PostgreSQL pool.
    #[command(flatten)]
    pub database: DatabaseArgs,
    /// AWS region of the message broker (required).
    #[arg(long = "aws-region", env = "AWS_REGION", hide_env_values = true)]
    pub aws_region: Option<String>,
    /// `http://` or `https://` endpoint of SQS (default: the regional AWS endpoint).
    #[arg(
        long = "aws-endpoint-url-sqs",
        env = "AWS_ENDPOINT_URL_SQS",
        hide_env_values = true
    )]
    pub aws_endpoint_url_sqs: Option<String>,
    /// Access key id; only validated as a pair with the secret, the AWS SDK reads it itself.
    #[arg(long, env = "AWS_ACCESS_KEY_ID", hide_env_values = true, hide = true)]
    pub aws_access_key_id: Option<String>,
    /// Secret access key; only validated as a pair with the key id, the AWS SDK reads it itself.
    #[arg(
        long,
        env = "AWS_SECRET_ACCESS_KEY",
        hide_env_values = true,
        hide = true
    )]
    pub aws_secret_access_key: Option<String>,
    /// Timeout of establishing an SQS connection (default 500ms).
    #[arg(
        long = "sqs-connect-timeout",
        env = "SQS_CONNECT_TIMEOUT",
        hide_env_values = true
    )]
    pub sqs_connect_timeout: Option<String>,
    /// Timeout of one SQS attempt and of the whole operation (default 2s).
    #[arg(
        long = "sqs-operation-timeout",
        env = "SQS_OPERATION_TIMEOUT",
        hide_env_values = true
    )]
    pub sqs_operation_timeout: Option<String>,
    /// SQS attempts per operation, 1 to 5 (default 1).
    #[arg(
        long = "sqs-max-attempts",
        env = "SQS_MAX_ATTEMPTS",
        hide_env_values = true
    )]
    pub sqs_max_attempts: Option<String>,
    /// Timeout of one health probe (default 3s).
    #[arg(
        long = "health-probe-timeout",
        env = "HEALTH_PROBE_TIMEOUT",
        hide_env_values = true
    )]
    pub health_probe_timeout: Option<String>,
    /// Budget of one HTTP request (default 10s).
    #[arg(
        long = "http-request-timeout",
        env = "HTTP_REQUEST_TIMEOUT",
        hide_env_values = true
    )]
    pub http_request_timeout: Option<String>,
    /// Largest accepted request body in bytes, 1024 to 10485760 (default 65536).
    #[arg(
        long = "http-max-body-bytes",
        env = "HTTP_MAX_BODY_BYTES",
        hide_env_values = true
    )]
    pub http_max_body_bytes: Option<String>,
    /// How long in-flight requests may finish after a termination signal (default 10s).
    #[arg(
        long = "shutdown-grace-period",
        env = "SHUTDOWN_GRACE_PERIOD",
        hide_env_values = true
    )]
    pub shutdown_grace_period: Option<String>,
    /// Settings of the offline validation of User service access tokens.
    #[command(flatten)]
    pub tokens: TokenArgs,
    /// Settings of the control-plane Kafka connection.
    #[command(flatten)]
    pub kafka: KafkaArgs,
    /// Settings of the maintenance task.
    #[command(flatten)]
    pub maintenance: MaintenanceArgs,
    /// Settings of the outbox relay.
    #[command(flatten)]
    pub relay: RelayArgs,
}

/// Settings of the maintenance task of `serve`.
#[derive(Debug, Clone, Default, Args)]
pub struct MaintenanceArgs {
    /// How often the maintenance task runs, a positive duration (default 10m).
    #[arg(
        long = "maintenance-interval",
        env = "MAINTENANCE_INTERVAL",
        hide_env_values = true
    )]
    pub interval: Option<String>,
    /// How long an orphaned grant is kept before the maintenance task purges it, a positive
    /// duration (default 90d).
    #[arg(
        long = "orphaned-grant-retention",
        env = "ORPHANED_GRANT_RETENTION",
        hide_env_values = true
    )]
    pub orphaned_grant_retention: Option<String>,
}

/// Settings of the outbox relay of `serve`.
#[derive(Debug, Clone, Default, Args)]
pub struct RelayArgs {
    /// `postgres://` or `postgresql://` URL of a direct (not pooled) connection that holds the
    /// `LISTEN iam_outbox` of the relay (default `DATABASE_URL`).
    #[arg(
        long = "database-listen-url",
        env = "DATABASE_LISTEN_URL",
        hide_env_values = true
    )]
    pub listen_url: Option<String>,
    /// `transaction.timeout.ms` of the transactional relay producer, from 1s to 10s (default
    /// 10s).
    #[arg(
        long = "kafka-transaction-timeout",
        env = "KAFKA_TRANSACTION_TIMEOUT",
        hide_env_values = true
    )]
    pub transaction_timeout: Option<String>,
}

/// Settings of `gateway`: the variables it shares with `serve` and its own.
#[derive(Debug, Clone, Default, Args)]
pub struct GatewayArgs {
    /// The variables of `serve`; the gateway reads `APP_ENV`, `LOG_LEVEL`, `SHUTDOWN_GRACE_PERIOD`
    /// and the token settings of them, and ignores the rest.
    #[command(flatten)]
    pub service: ServeArgs,
    /// Address of the public listener (default `0.0.0.0:8443`).
    #[arg(
        long = "gateway-listen",
        env = "GATEWAY_LISTEN",
        hide_env_values = true
    )]
    pub listen: Option<String>,
    /// Address of the internal listener for `iam-control` and the gateway pods (default
    /// `0.0.0.0:9090`).
    #[arg(
        long = "gateway-internal-listen",
        env = "GATEWAY_INTERNAL_LISTEN",
        hide_env_values = true
    )]
    pub internal_listen: Option<String>,
    /// Address of the probe listener (default `0.0.0.0:9092`).
    #[arg(
        long = "gateway-probe-listen",
        env = "GATEWAY_PROBE_LISTEN",
        hide_env_values = true
    )]
    pub probe_listen: Option<String>,
    /// PEM file of the certificate chain of the public listener, hot-reloaded; required with
    /// `GATEWAY_TLS_KEY_FILE`, and outside `APP_ENV` `dev` and `test` always.
    #[arg(
        long = "gateway-tls-cert-file",
        env = "GATEWAY_TLS_CERT_FILE",
        hide_env_values = true
    )]
    pub tls_cert_file: Option<String>,
    /// PEM file of the private key of the public listener, hot-reloaded; required with
    /// `GATEWAY_TLS_CERT_FILE`, and outside `APP_ENV` `dev` and `test` always.
    #[arg(
        long = "gateway-tls-key-file",
        env = "GATEWAY_TLS_KEY_FILE",
        hide_env_values = true
    )]
    pub tls_key_file: Option<String>,
    /// Name of the pod, from the Kubernetes downward API.
    #[arg(long = "pod-name", env = "POD_NAME", hide_env_values = true)]
    pub pod_name: Option<String>,
    /// Namespace of the pod, from the Kubernetes downward API.
    #[arg(long = "pod-namespace", env = "POD_NAMESPACE", hide_env_values = true)]
    pub pod_namespace: Option<String>,
    /// How the gateway discovers upstream endpoints: `kubernetes` (default) or `static`.
    #[arg(
        long = "upstream-discovery",
        env = "UPSTREAM_DISCOVERY",
        hide_env_values = true
    )]
    pub upstream_discovery: Option<String>,
    /// JSON file of the upstream endpoints; required with `UPSTREAM_DISCOVERY=static`.
    #[arg(
        long = "upstream-static-endpoints-file",
        env = "UPSTREAM_STATIC_ENDPOINTS_FILE",
        hide_env_values = true
    )]
    pub upstream_static_endpoints_file: Option<String>,
    /// Whether requests prefer the endpoints of the gateway's own zone (default `true`).
    #[arg(
        long = "upstream-zone-aware",
        env = "UPSTREAM_ZONE_AWARE",
        hide_env_values = true
    )]
    pub upstream_zone_aware: Option<String>,
    /// The zone of this gateway pod; unset, it is taken from the pod's entry in the
    /// `iam-gateway-peers` `EndpointSlices`.
    #[arg(long = "gateway-zone", env = "GATEWAY_ZONE", hide_env_values = true)]
    pub gateway_zone: Option<String>,
}

/// Arguments of `check-config`: the run mode and the settings of both modes.
#[derive(Debug, Clone, Default, Args)]
pub struct CheckConfigArgs {
    /// The run mode to validate: `control` (default) or `gateway`.
    #[arg(long, value_enum, default_value_t = Mode::Control)]
    pub mode: Mode,
    /// The settings of both modes.
    #[command(flatten)]
    pub gateway: GatewayArgs,
}

/// Settings of the control-plane Kafka connection and of the topics it works on.
#[derive(Debug, Clone, Default, Args)]
pub struct KafkaArgs {
    /// Comma-separated `host:port` pairs of the Kafka bootstrap servers (required).
    #[arg(
        long = "kafka-bootstrap-servers",
        env = "KAFKA_BOOTSTRAP_SERVERS",
        hide_env_values = true
    )]
    pub bootstrap_servers: Option<String>,
    /// `SASL_SSL` or `PLAINTEXT`; `PLAINTEXT` only when `APP_ENV` is `dev` or `test` (default
    /// `SASL_SSL`).
    #[arg(
        long = "kafka-security-protocol",
        env = "KAFKA_SECURITY_PROTOCOL",
        hide_env_values = true
    )]
    pub security_protocol: Option<String>,
    /// `SCRAM-SHA-512` or `SCRAM-SHA-256` (default `SCRAM-SHA-512`).
    #[arg(
        long = "kafka-sasl-mechanism",
        env = "KAFKA_SASL_MECHANISM",
        hide_env_values = true
    )]
    pub sasl_mechanism: Option<String>,
    /// SASL user name (required with `SASL_SSL`).
    #[arg(
        long = "kafka-sasl-username",
        env = "KAFKA_SASL_USERNAME",
        hide_env_values = true
    )]
    pub sasl_username: Option<String>,
    /// SASL password (required with `SASL_SSL`).
    #[arg(
        long = "kafka-sasl-password",
        env = "KAFKA_SASL_PASSWORD",
        hide_env_values = true
    )]
    pub sasl_password: Option<String>,
    /// PEM file of the certificate authority to trust instead of the system roots.
    #[arg(long = "kafka-ca-file", env = "KAFKA_CA_FILE", hide_env_values = true)]
    pub ca_file: Option<String>,
    /// Client id of the connection (default `iam-control`).
    #[arg(
        long = "kafka-client-id",
        env = "KAFKA_CLIENT_ID",
        hide_env_values = true
    )]
    pub client_id: Option<String>,
    /// Timeout of opening a Kafka connection (default 1s).
    #[arg(
        long = "kafka-connect-timeout",
        env = "KAFKA_CONNECT_TIMEOUT",
        hide_env_values = true
    )]
    pub connect_timeout: Option<String>,
    /// Timeout of one Kafka request, at least `KAFKA_CONNECT_TIMEOUT` (default 2s).
    #[arg(
        long = "kafka-request-timeout",
        env = "KAFKA_REQUEST_TIMEOUT",
        hide_env_values = true
    )]
    pub request_timeout: Option<String>,
    /// Pause between two attempts of a retried Kafka request (default 100ms).
    #[arg(
        long = "kafka-retry-delay",
        env = "KAFKA_RETRY_DELAY",
        hide_env_values = true
    )]
    pub retry_delay: Option<String>,
    /// `enforce` or `relaxed`; `relaxed` only when `APP_ENV` is `dev` or `test` (default
    /// `enforce`).
    #[arg(
        long = "kafka-config-gates",
        env = "KAFKA_CONFIG_GATES",
        hide_env_values = true
    )]
    pub config_gates: Option<String>,
    /// The state topic of the IAM policy log (default `iam.policy.state.v1`).
    #[arg(long = "policy-topic", env = "POLICY_TOPIC", hide_env_values = true)]
    pub policy_topic: Option<String>,
    /// The topic of the IAM events (default `iam.events.v1`).
    #[arg(long = "events-topic", env = "EVENTS_TOPIC", hide_env_values = true)]
    pub events_topic: Option<String>,
}

/// Settings of the offline validation of User service access tokens.
#[derive(Debug, Clone, Default, Args)]
pub struct TokenArgs {
    /// File of 1 to 3 PEM RSA public keys, newest last, reloaded when it changes (required).
    #[arg(
        long = "jwt-public-keys-file",
        env = "JWT_PUBLIC_KEYS_FILE",
        hide_env_values = true
    )]
    pub public_keys_file: Option<String>,
    /// Required `iss` of every token (default `vilnacrm-user-service`).
    #[arg(long = "jwt-issuer", env = "JWT_ISSUER", hide_env_values = true)]
    pub issuer: Option<String>,
    /// Audience every token's `aud` must contain (default `vilnacrm-api`).
    #[arg(long = "jwt-audience", env = "JWT_AUDIENCE", hide_env_values = true)]
    pub audience: Option<String>,
    /// Tolerated clock difference to the token issuer, at most 60s (default 30s).
    #[arg(
        long = "jwt-clock-skew",
        env = "JWT_CLOCK_SKEW",
        hide_env_values = true
    )]
    pub clock_skew: Option<String>,
    /// Longest accepted `exp - iat` of a token (default 900s).
    #[arg(
        long = "max-token-lifetime",
        env = "MAX_TOKEN_LIFETIME",
        hide_env_values = true
    )]
    pub max_token_lifetime: Option<String>,
    /// Largest number of memoized token identities, at least 1000 (default 200000).
    #[arg(
        long = "token-memo-capacity",
        env = "TOKEN_MEMO_CAPACITY",
        hide_env_values = true
    )]
    pub memo_capacity: Option<String>,
    /// Longest time a token identity is memoized, at most `MAX_TOKEN_LIFETIME` (default 900s).
    #[arg(
        long = "token-memo-max-ttl",
        env = "TOKEN_MEMO_MAX_TTL",
        hide_env_values = true
    )]
    pub memo_max_ttl: Option<String>,
    /// Audience a service caller's token must contain to call IAM (default `vilnacrm-iam`).
    #[arg(
        long = "jwt-caller-audience",
        env = "JWT_CALLER_AUDIENCE",
        hide_env_values = true
    )]
    pub caller_audience: Option<String>,
    /// Longest accepted `exp - iat` of a service caller's token, at most 3600s and at most
    /// `MAX_TOKEN_LIFETIME` (default 900s).
    #[arg(
        long = "jwt-service-token-max-lifetime",
        env = "JWT_SERVICE_TOKEN_MAX_LIFETIME",
        hide_env_values = true
    )]
    pub service_token_max_lifetime: Option<String>,
}

/// Settings of `migrate` and `migrate revert`.
#[derive(Debug, Clone, Args)]
pub struct MigrateArgs {
    /// Settings of the PostgreSQL pool.
    #[command(flatten)]
    pub database: DatabaseArgs,
    /// How long to wait for the database, one attempt per second (default 30s).
    #[arg(
        long = "wait-timeout",
        env = "DATABASE_WAIT_TIMEOUT",
        hide_env_values = true
    )]
    pub wait_timeout: Option<String>,
    /// Revert instead of apply.
    #[command(subcommand)]
    pub action: Option<MigrateAction>,
}

/// Settings of `iam-bootstrap`: the settings of `serve` and the subject of the first administrator.
#[derive(Debug, Clone, Default, Args)]
pub struct IamBootstrapArgs {
    /// Settings of the service: the bootstrap connects as `serve` does.
    #[command(flatten)]
    pub service: ServeArgs,
    /// UUID of the user who becomes the first administrator; exactly one of `--admin-user` and
    /// `--admin-service` is required.
    #[arg(long = "admin-user")]
    pub admin_user: Option<String>,
    /// Service name of the service principal that becomes the first administrator; exactly one of
    /// `--admin-user` and `--admin-service` is required.
    #[arg(long = "admin-service")]
    pub admin_service: Option<String>,
}

/// Arguments of `openapi-export` and `graphql-export`.
#[derive(Debug, Clone, Args)]
pub struct ExportArgs {
    /// File to write; standard output when absent.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

/// Arguments of `healthcheck`.
#[derive(Debug, Clone, Args)]
pub struct HealthcheckArgs {
    /// The run mode to probe: `control` (default) probes `/ping` on the service port, `gateway`
    /// probes `/ping` on the probe listener.
    #[arg(long, value_enum, default_value_t = Mode::Control)]
    pub mode: Mode,
    /// Address of the probe listener of the gateway (default `0.0.0.0:9092`).
    #[arg(
        long = "gateway-probe-listen",
        env = "GATEWAY_PROBE_LISTEN",
        hide_env_values = true
    )]
    pub probe_listen: Option<String>,
    /// TCP port of the service (default 8081).
    #[arg(long = "port", env = "APP_PORT", hide_env_values = true)]
    pub port: Option<String>,
    /// IP address the service listens on; the loopback interface is probed when it is an
    /// unspecified address such as `0.0.0.0` (default `127.0.0.1`).
    #[arg(long = "host", env = "APP_HOST", hide_env_values = true)]
    pub host: Option<String>,
}

#[cfg(test)]
mod tests;
