//! Typed configuration of the service, parsed and validated from the command-line arguments.
//!
//! [`Config::from_args`] collects every problem instead of stopping at the first one. A problem
//! names the environment variable and a reason that never contains a value, so a secret that is
//! malformed is not echoed.

use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr};
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use axum::http::Uri;
use axum::http::uri::Authority;
use iam_domain::{CallerTokenRule, TokenLifetimeRule};
use iam_infrastructure::{JwtKeySet, JwtSettings, TokenMemoSettings};
use shared_infrastructure::messaging::SqsSettings;
use shared_infrastructure::persistence::{
    MAX_STATEMENT_TIMEOUT, MIN_STATEMENT_TIMEOUT, PostgresSettings,
};
use sqlx::postgres::PgConnectOptions;
use tracing_subscriber::EnvFilter;

use crate::cli::{DatabaseArgs, MigrateArgs, ServeArgs, TokenArgs};

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
        let tokens = tokens(&mut collector, &args.tokens);
        collector.cross_field_rules(
            database.as_ref().map(|settings| settings.acquire_timeout),
            sqs.as_ref().map(|settings| settings.operation_timeout),
            limits.as_ref().map(|limits| limits.health_probe_timeout),
            limits.as_ref().map(|limits| limits.request_timeout),
        );
        match (server, database, sqs, limits, tokens) {
            (Some(server), Some(database), Some(sqs), Some(limits), Some(tokens))
                if collector.problems.is_empty() =>
            {
                Ok(Self {
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
                })
            }
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

    fn cross_field_rules(
        &mut self,
        acquire: Option<Duration>,
        operation: Option<Duration>,
        probe: Option<Duration>,
        request: Option<Duration>,
    ) {
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
    Some(Limits {
        health_probe_timeout: probe?,
        request_timeout: request?,
        max_body_bytes: body?,
        shutdown_grace_period: grace?,
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
