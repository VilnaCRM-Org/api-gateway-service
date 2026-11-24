//! The world of a scenario: injected faults, the last response, the created ids and the scenario
//! database. A new application instance is built for every request.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::str::FromStr as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, Request, header};
use clap::Parser as _;
use health_check_domain::Dependency;
use http_body_util::BodyExt as _;
use iam_domain::{
    ActorRef, PolicyEpoch, RejectedAttemptLog, RevocationSource, SessionId, SessionRevocation,
    SessionRevocationId, SubjectRef, SystemComponent,
};
use serde_json::Value;
use service::bootstrap::{
    Adapters, TaskMode, TaskSupervisor, bootstrap_administrator, register_iam_specs, router,
    singleton_set, start_tasks,
};
use service::cli::{Cli, Command};
use service::config::Config;
use shared_domain::Uuid;
use shared_infrastructure::persistence::MIGRATOR;
use sqlx::postgres::PgConnectOptions;
use sqlx::{AssertSqlSafe, ConnectOptions as _, Connection as _, PgConnection};
use test_support::probe::StubProbe;
use tokio::sync::watch;
use tower::ServiceExt as _;

use crate::administrator_policy::AdministratorCallerPolicy;
use crate::events_topic::{self, EventRecord};
use crate::tokens::{SigningKey, USER_ID, instant_after};

/// Counter that makes the database names of the scenarios of one process unique.
static DATABASES: AtomicUsize = AtomicUsize::new(0);

/// Counter that makes the key file names of the scenarios of one process unique.
static KEY_FILES: AtomicUsize = AtomicUsize::new(0);

/// The token that stands for the remembered id in paths, doc strings and string arguments.
const ID_TOKEN: &str = "{id}";

/// The token that stands for the subject credential of the scenario.
const SUBJECT_TOKEN: &str = "{token}";

/// The token that stands for the remembered page cursor.
const CURSOR_TOKEN: &str = "{cursor}";

/// The token that stands for the id of the role that a step seeded.
const ROLE_TOKEN: &str = "{role}";

/// The id of the active global assignment of `iam-platform-admin` that belongs to the user.
const ADMINISTRATOR_ASSIGNMENT: &str = "SELECT assignments.id::text FROM iam_user_roles assignments \
     JOIN iam_roles roles ON roles.id = assignments.role_id \
     WHERE roles.name = 'iam-platform-admin' AND assignments.subject_kind = 'user' \
     AND assignments.subject_id = $1 AND assignments.revoked_at IS NULL";

/// The id of the role that the bootstrap created.
const ADMINISTRATOR_ROLE: &str = "SELECT id::text FROM iam_roles WHERE name = $1";

/// How long a session revocation recorded by a step is kept before it may be pruned.
const REVOCATION_RETENTION: Duration = Duration::from_hours(24);

/// How long the per-replica tasks of a scenario get to stop before the scenario database is dropped.
const TASK_STOP_GRACE: Duration = Duration::from_secs(5);

/// How long a step waits for the relay to publish the outbox rows of a scenario.
const RELAY_DEADLINE: Duration = Duration::from_secs(30);

/// The pause between two looks at the unpublished rows of a scenario.
const RELAY_POLL: Duration = Duration::from_millis(100);

/// What the last request answered.
#[derive(Debug, Clone)]
pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) headers: HeaderMap,
    pub(crate) body: String,
}

impl Reply {
    /// The body as JSON, `Null` when it is not JSON.
    pub(crate) fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

/// One instance per scenario; cucumber builds it with `Default`.
#[derive(Debug, Default, cucumber::World)]
pub(crate) struct AppWorld {
    failing: Vec<Dependency>,
    database: Option<String>,
    /// The topic of the scenario's events on the compose broker; created with the database.
    events_topic: Option<String>,
    reply: Option<Reply>,
    created: Vec<String>,
    remembered: Option<String>,
    history: Vec<Reply>,
    signing: Option<SigningKey>,
    key_file: Option<PathBuf>,
    caller_token: Option<String>,
    subject_token: Option<String>,
    idempotency_key: Option<String>,
    if_match: Option<String>,
    prefer: Option<String>,
    cursor: Option<String>,
    role: Option<String>,
    tasks: Option<(watch::Sender<bool>, TaskSupervisor)>,
    /// The buffer of rejected attempts that the writer of the per-replica tasks flushes; every
    /// application instance of the scenario offers its refusals to it, as one `service serve`
    /// process does.
    rejected_attempts: Option<Arc<dyn RejectedAttemptLog>>,
}

/// The configuration as the binary reads it from the environment.
fn base_config() -> Config {
    let Command::Serve(args) = Cli::parse_from(["service", "serve"]).command else {
        panic!("`serve` arguments expected");
    };
    let mut config = Config::from_args(args).expect("valid configuration");
    // The production defaults are a few seconds. A scenario must succeed however long the machine
    // needs to open the first connection, so the budgets are long and keep the order the
    // configuration requires (request > probe >= acquire and operation).
    config.database.acquire_timeout = Duration::from_secs(30);
    config.sqs.connect_timeout = Duration::from_secs(10);
    config.sqs.operation_timeout = Duration::from_secs(30);
    config.health_probe_timeout = Duration::from_secs(40);
    config.request_timeout = Duration::from_secs(60);
    config
}

/// The bootstrap servers of the compose broker, as `KAFKA_BOOTSTRAP_SERVERS` names them.
fn kafka_servers() -> String {
    base_config().kafka.bootstrap_servers
}

/// Connection options of the server of `DATABASE_URL`.
fn server_options() -> PgConnectOptions {
    PgConnectOptions::from_str(&base_config().database.url).expect("valid database URL")
}

/// A connection to the server of `DATABASE_URL`, used to create and drop databases.
async fn admin() -> PgConnection {
    server_options()
        .connect()
        .await
        .expect("the database server is reachable")
}

/// Drops every database a killed run left behind (and, with it, any other `e2e_` database: two
/// runs must not share a server at the same time).
pub(crate) async fn drop_leftover_databases() {
    let mut connection = admin().await;
    let names: Vec<String> =
        sqlx::query_scalar("SELECT datname FROM pg_database WHERE datname LIKE 'e2e\\_%'")
            .fetch_all(&mut connection)
            .await
            .expect("list the leftover databases");
    for name in names {
        drop_named(&mut connection, &name).await;
    }
}

async fn drop_named(connection: &mut PgConnection, name: &str) {
    let statement = format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)");
    sqlx::query(AssertSqlSafe(statement))
        .execute(connection)
        .await
        .expect("drop the database");
}

impl AppWorld {
    /// Marks a dependency as failing: its probe is replaced before the next request.
    pub(crate) fn fail(&mut self, dependency: Dependency) {
        self.failing.push(dependency);
    }

    /// The last response.
    pub(crate) fn reply(&self) -> &Reply {
        self.reply.as_ref().expect("a request was sent")
    }

    /// The ids of the resources the scenario created.
    pub(crate) fn created(&self) -> BTreeSet<String> {
        self.created.iter().cloned().collect()
    }

    /// Asserts that the ids of the JSON array are exactly the created ids, and that there are some.
    pub(crate) fn assert_exactly_created(&self, array: &Value) {
        let ids: BTreeSet<String> = array
            .as_array()
            .expect("a JSON array")
            .iter()
            .filter_map(|item| item.get("id").and_then(Value::as_str))
            .map(str::to_owned)
            .collect();
        let created = self.created();
        assert!(!created.is_empty(), "the scenario created no resource");
        assert_eq!(ids, created);
    }

    /// The id that an earlier step remembered.
    ///
    /// # Panics
    ///
    /// When no step remembered an id.
    pub(crate) fn remembered_id(&self) -> &str {
        self.remembered.as_deref().expect("a remembered id")
    }

    /// Replaces the `{id}` token by the remembered id and the `{token}` token by the subject
    /// credential.
    pub(crate) fn substitute(&self, text: &str) -> String {
        let text = self
            .remembered
            .as_deref()
            .map_or_else(|| text.to_owned(), |id| text.replace(ID_TOKEN, id));
        let text = self
            .cursor
            .as_deref()
            .map_or_else(|| text.clone(), |cursor| text.replace(CURSOR_TOKEN, cursor));
        let text = self
            .role
            .as_deref()
            .map_or_else(|| text.clone(), |role| text.replace(ROLE_TOKEN, role));
        self.subject_token
            .as_deref()
            .map_or_else(|| text.clone(), |token| text.replace(SUBJECT_TOKEN, token))
    }

    /// Makes the following requests carry this `Idempotency-Key` header.
    pub(crate) fn set_idempotency_key(&mut self, key: String) {
        self.idempotency_key = Some(key);
    }

    /// Makes the following requests carry this `Prefer` header.
    pub(crate) fn set_prefer(&mut self, value: String) {
        self.prefer = Some(value);
    }

    /// Makes the following requests carry this `If-Match` header.
    pub(crate) fn set_if_match(&mut self, value: String) {
        self.if_match = Some(value);
    }

    /// The digest that the newest `__head` state row of the outbox ends with, in the scenario
    /// database.
    pub(crate) async fn latest_head_digest(&mut self) -> Vec<u8> {
        let url = self.database_url().await;
        let options = PgConnectOptions::from_str(&url).expect("valid database URL");
        let mut connection = options
            .connect()
            .await
            .expect("connect to the scenario database");
        let digest = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT digest_after FROM iam_outbox WHERE kind = 'state' AND record_key = '__head' \
             ORDER BY position DESC LIMIT 1",
        )
        .fetch_one(&mut connection)
        .await
        .expect("the newest head row");
        connection.close().await.expect("close");
        digest
    }

    /// The stored offset of the published `__head` row of policy version `version` in the
    /// scenario database; `None` when the relay stored none.
    pub(crate) async fn stored_head_offset(&mut self, version: i64) -> Option<i64> {
        let url = self.database_url().await;
        let options = PgConnectOptions::from_str(&url).expect("valid database URL");
        let mut connection = options
            .connect()
            .await
            .expect("connect to the scenario database");
        let offset = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT published_offset FROM iam_outbox \
             WHERE kind = 'state' AND record_key = '__head' AND policy_version = $1 \
                 AND published_at IS NOT NULL \
             ORDER BY seq DESC NULLS LAST LIMIT 1",
        )
        .bind(version)
        .fetch_optional(&mut connection)
        .await
        .expect("the head row query")
        .flatten();
        connection.close().await.expect("close");
        offset
    }

    /// Stores a system role named `name` at version 1 in the scenario database, as a fixture,
    /// and remembers its id for `{id}`.
    pub(crate) async fn seed_system_role(&mut self, name: &str) {
        let url = self.database_url().await;
        let options = PgConnectOptions::from_str(&url).expect("valid database URL");
        let mut connection = options
            .connect()
            .await
            .expect("connect to the scenario database");
        let id = sqlx::query_scalar::<_, String>(
            "INSERT INTO iam_roles (id, name, description, kind, grant_count, version, \
             created_at, updated_at) \
             VALUES (gen_random_uuid(), $1, NULL, 'system', 0, 1, now(), now()) RETURNING id::text",
        )
        .bind(name.to_owned())
        .fetch_one(&mut connection)
        .await
        .expect("seed the system role");
        connection.close().await.expect("close");
        self.remembered = Some(id);
    }

    /// Stores the upstream `name` of the catalogue service `catalog_service` at version 1 in the
    /// scenario database, as a fixture, and remembers its id for `{id}`. A `system` upstream is
    /// one that the API refuses to change.
    pub(crate) async fn seed_upstream(&mut self, name: &str, catalog_service: &str, system: bool) {
        let url = self.database_url().await;
        let options = PgConnectOptions::from_str(&url).expect("valid database URL");
        let mut connection = options
            .connect()
            .await
            .expect("connect to the scenario database");
        let id = sqlx::query_scalar::<_, String>(
            "INSERT INTO iam_upstreams (id, name, namespace, service_name, catalog_service, port, \
             protocol, forward_credentials, system, connect_timeout_ms, response_timeout_ms, \
             concurrency_limit, retry_budget_percent, outlier_threshold, version, created_at, \
             updated_at) \
             VALUES (gen_random_uuid(), $1, 'platform', $1, $2, 8080, 'http1', FALSE, $3, 250, \
             10000, 256, 10, 5, 1, now(), now()) RETURNING id::text",
        )
        .bind(name.to_owned())
        .bind(catalog_service.to_owned())
        .bind(system)
        .fetch_one(&mut connection)
        .await
        .expect("seed the upstream");
        connection.close().await.expect("close");
        self.remembered = Some(id);
    }

    /// Stores a route that forwards to the upstream `name` in the scenario database, as a fixture:
    /// the state that a route write leaves behind.
    pub(crate) async fn seed_route_to_upstream(&mut self, name: &str) {
        let url = self.database_url().await;
        let options = PgConnectOptions::from_str(&url).expect("valid database URL");
        let mut connection = options
            .connect()
            .await
            .expect("connect to the scenario database");
        sqlx::query(
            "INSERT INTO iam_routes (id, host, methods, path_pattern, service, upstream_id, \
             enforcement, body_limit, request_timeout_ms, idle_timeout_ms, retry, version, \
             created_at, updated_at) \
             SELECT gen_random_uuid(), 'api.example.com', ARRAY['GET'], '/seeded', \
             catalog_service, id, 'enforce', 1048576, 30000, 60000, 'none', 1, now(), now() \
             FROM iam_upstreams WHERE name = $1 AND deleted_at IS NULL",
        )
        .bind(name.to_owned())
        .execute(&mut connection)
        .await
        .expect("seed the route");
        connection.close().await.expect("close");
    }

    /// Stores a system route of the service `iam` on `host` for `path_pattern` that forwards to
    /// the upstream `upstream` in the scenario database, as a fixture, and remembers its id for
    /// `{id}`: the API refuses every change of such a route.
    pub(crate) async fn seed_system_route(
        &mut self,
        host: &str,
        path_pattern: &str,
        upstream: &str,
    ) {
        let url = self.database_url().await;
        let options = PgConnectOptions::from_str(&url).expect("valid database URL");
        let mut connection = options
            .connect()
            .await
            .expect("connect to the scenario database");
        let id = sqlx::query_scalar::<_, String>(
            "INSERT INTO iam_routes (id, host, methods, path_pattern, service, upstream_id, \
             enforcement, body_limit, request_timeout_ms, idle_timeout_ms, retry, system, \
             version, created_at, updated_at) \
             SELECT gen_random_uuid(), $1, ARRAY['GET'], $2, 'iam', id, 'enforce', 1048576, \
             30000, 60000, 'none', TRUE, 1, now(), now() \
             FROM iam_upstreams WHERE name = $3 AND deleted_at IS NULL RETURNING id::text",
        )
        .bind(host.to_owned())
        .bind(path_pattern.to_owned())
        .bind(upstream.to_owned())
        .fetch_one(&mut connection)
        .await
        .expect("seed the system route");
        connection.close().await.expect("close");
        self.remembered = Some(id);
    }

    /// Stores an upstream and a route that applies the remembered rate policy in the scenario
    /// database, as a fixture: the state that a route write leaves behind.
    pub(crate) async fn seed_route_with_remembered_rate_policy(&mut self) {
        let policy = self
            .remembered
            .clone()
            .expect("a rate policy was created before the route is seeded");
        let url = self.database_url().await;
        let options = PgConnectOptions::from_str(&url).expect("valid database URL");
        let mut connection = options
            .connect()
            .await
            .expect("connect to the scenario database");
        let upstream = sqlx::query_scalar::<_, String>(
            "INSERT INTO iam_upstreams (id, name, namespace, service_name, catalog_service, port, \
             protocol, forward_credentials, system, connect_timeout_ms, response_timeout_ms, \
             concurrency_limit, retry_budget_percent, outlier_threshold, version, created_at, \
             updated_at) \
             VALUES (gen_random_uuid(), 'seeded-upstream', 'default', 'seeded', 'seeded', 80, \
             'http1', FALSE, FALSE, 1000, 30000, 1000, 20, 5, 1, now(), now()) RETURNING id::text",
        )
        .fetch_one(&mut connection)
        .await
        .expect("seed the upstream");
        let route = sqlx::query_scalar::<_, String>(
            "INSERT INTO iam_routes (id, host, methods, path_pattern, service, upstream_id, \
             enforcement, body_limit, request_timeout_ms, idle_timeout_ms, retry, version, \
             created_at, updated_at) \
             VALUES (gen_random_uuid(), 'api.example.com', ARRAY['GET'], '/seeded', 'seeded', \
             $1::text::uuid, 'enforce', 1048576, 30000, 60000, 'none', 1, now(), now()) \
             RETURNING id::text",
        )
        .bind(upstream)
        .fetch_one(&mut connection)
        .await
        .expect("seed the route");
        sqlx::query(
            "INSERT INTO iam_route_rate_policies (route_id, rate_policy_id, position) \
             VALUES ($1::text::uuid, $2::text::uuid, 1)",
        )
        .bind(route)
        .bind(policy)
        .execute(&mut connection)
        .await
        .expect("seed the route's rate policy");
        connection.close().await.expect("close");
    }

    /// Stores a custom role named `name` at version 1 that grants `keys` in the scenario database,
    /// as a fixture, and remembers its id for `{role}`.
    pub(crate) async fn seed_role(&mut self, name: &str, keys: &[String]) {
        let url = self.database_url().await;
        let options = PgConnectOptions::from_str(&url).expect("valid database URL");
        let mut connection = options
            .connect()
            .await
            .expect("connect to the scenario database");
        let id = sqlx::query_scalar::<_, String>(
            "INSERT INTO iam_roles (id, name, description, kind, grant_count, version, \
             created_at, updated_at) \
             VALUES (gen_random_uuid(), $1, NULL, 'custom', $2, 1, now(), now()) RETURNING id::text",
        )
        .bind(name.to_owned())
        .bind(i32::try_from(keys.len()).expect("a few grants"))
        .fetch_one(&mut connection)
        .await
        .expect("seed the role");
        for key in keys {
            sqlx::query(
                "INSERT INTO iam_role_permissions (role_id, permission_key, key_kind, service, \
                 is_wildcard, active, granted_by, granted_at) \
                 VALUES ($1::text::uuid, $2, split_part($2, ':', 1), \
                 CASE WHEN split_part($2, ':', 1) = 'iam' THEN 'iam' ELSE split_part($2, ':', 2) END, \
                 ($2 LIKE '%*%' AND $2 NOT LIKE 'iam:%'), TRUE, 'system:bootstrap', now())",
            )
            .bind(id.clone())
            .bind(key.clone())
            .execute(&mut connection)
            .await
            .expect("seed the grant");
        }
        connection.close().await.expect("close");
        self.role = Some(id);
    }

    /// Stores the inactive GraphQL catalogue entry `key` in the scenario database, as a fixture: the
    /// state that an earlier, retired version leaves behind.
    pub(crate) async fn seed_inactive_catalogue_entry(&mut self, key: &str, sensitive: bool) {
        let url = self.database_url().await;
        let options = PgConnectOptions::from_str(&url).expect("valid database URL");
        let mut connection = options
            .connect()
            .await
            .expect("connect to the scenario database");
        sqlx::query(
            "INSERT INTO iam_graphql_permissions (id, permission_key, service, type_name, \
             field_name, sensitive, audit_always, active, orphaned_at, created_at) \
             VALUES (gen_random_uuid(), $1, split_part($1, ':', 2), \
             split_part(split_part($1, ':', 3), '.', 1), \
             split_part(split_part($1, ':', 3), '.', 2), $2, FALSE, FALSE, NULL, now())",
        )
        .bind(key.to_owned())
        .bind(sensitive)
        .execute(&mut connection)
        .await
        .expect("seed the catalogue entry");
        connection.close().await.expect("close");
    }

    /// Stores the inactive REST catalogue entry `key` in the scenario database, as a fixture: the
    /// state that an earlier, retired version leaves behind.
    pub(crate) async fn seed_inactive_rest_catalogue_entry(&mut self, key: &str, sensitive: bool) {
        let url = self.database_url().await;
        let options = PgConnectOptions::from_str(&url).expect("valid database URL");
        let mut connection = options
            .connect()
            .await
            .expect("connect to the scenario database");
        sqlx::query(
            "INSERT INTO iam_rest_permissions (id, permission_key, service, method, \
             path_template, sensitive, audit_always, active, orphaned_at, created_at) \
             VALUES (gen_random_uuid(), $1, split_part($1, ':', 2), \
             split_part(split_part($1, ':', 3), ' ', 1), \
             substr(split_part($1, ':', 3), strpos(split_part($1, ':', 3), ' ') + 1), \
             $2, FALSE, FALSE, NULL, now())",
        )
        .bind(key.to_owned())
        .bind(sensitive)
        .execute(&mut connection)
        .await
        .expect("seed the catalogue entry");
        connection.close().await.expect("close");
    }

    /// Stores `count` active assignments of the seeded role to distinct users in the scenario
    /// database, as a fixture: the only fast way to have a role that a bulk operation must delete.
    pub(crate) async fn seed_assignments(&mut self, count: i64) {
        let url = self.database_url().await;
        let options = PgConnectOptions::from_str(&url).expect("valid database URL");
        let mut connection = options
            .connect()
            .await
            .expect("connect to the scenario database");
        sqlx::query(
            "INSERT INTO iam_user_roles (id, subject_kind, subject_id, role_id, scope_kind, \
             version, created_by, created_at, updated_at) \
             SELECT gen_random_uuid(), 'user', gen_random_uuid()::text, $1::text::uuid, 'global', \
             1, 'system:bootstrap', now(), now() FROM generate_series(1, $2)",
        )
        .bind(self.seeded_role().to_owned())
        .bind(count)
        .execute(&mut connection)
        .await
        .expect("seed the assignments");
        connection.close().await.expect("close");
    }

    /// Waits until no bulk operation of the scenario database is pending or running.
    ///
    /// # Panics
    ///
    /// When an operation is still unfinished after the wait.
    pub(crate) async fn wait_for_bulk_operations(&mut self) {
        let url = self.database_url().await;
        let options = PgConnectOptions::from_str(&url).expect("valid database URL");
        let mut connection = options
            .connect()
            .await
            .expect("connect to the scenario database");
        for _attempt in 0..120 {
            let unfinished = sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM iam_bulk_operations WHERE status IN ('pending', 'running')",
            )
            .fetch_one(&mut connection)
            .await
            .expect("count the unfinished bulk operations");
            if unfinished == 0 {
                connection.close().await.expect("close");
                return;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        panic!("a bulk operation is still unfinished after a minute");
    }

    /// Makes every update of an assignment row of the scenario database fail, as a fixture: the
    /// statement that a role deletion runs after it has updated the role row, so that the whole
    /// change must roll back.
    pub(crate) async fn force_assignment_updates_to_fail(&mut self) {
        let url = self.database_url().await;
        let options = PgConnectOptions::from_str(&url).expect("valid database URL");
        let mut connection = options
            .connect()
            .await
            .expect("connect to the scenario database");
        sqlx::query(
            "CREATE FUNCTION iam_forced_failure() RETURNS trigger LANGUAGE plpgsql AS \
             $$ BEGIN RAISE EXCEPTION 'forced failure of the statement'; END $$",
        )
        .execute(&mut connection)
        .await
        .expect("create the failing function");
        sqlx::query(
            "CREATE TRIGGER iam_forced_failure BEFORE UPDATE ON iam_user_roles \
             FOR EACH ROW EXECUTE FUNCTION iam_forced_failure()",
        )
        .execute(&mut connection)
        .await
        .expect("create the failing trigger");
        connection.close().await.expect("close");
    }

    /// Marks the GraphQL specification version that `{id}` stands for as active in the scenario
    /// database, as a fixture: the only way to have an active version before the activation
    /// operation exists.
    pub(crate) async fn activate_remembered_graphql_spec(&mut self) {
        let id = self
            .remembered
            .clone()
            .expect("a step remembered a GraphQL specification");
        let url = self.database_url().await;
        let options = PgConnectOptions::from_str(&url).expect("valid database URL");
        let mut connection = options
            .connect()
            .await
            .expect("connect to the scenario database");
        let activated = sqlx::query(
            "UPDATE iam_graphql_specs SET status = 'active', activated_at = now() \
             WHERE id = $1::text::uuid AND status = 'draft'",
        )
        .bind(id)
        .execute(&mut connection)
        .await
        .expect("activate the version")
        .rows_affected();
        assert_eq!(activated, 1, "the remembered id names a draft version");
        connection.close().await.expect("close");
    }

    /// Marks the `OpenAPI` specification version that `{id}` stands for as active in the scenario
    /// database, as a fixture: the only way to have an active version before the activation
    /// operation exists.
    pub(crate) async fn activate_remembered_openapi_spec(&mut self) {
        let id = self
            .remembered
            .clone()
            .expect("a step remembered an OpenAPI specification");
        let url = self.database_url().await;
        let options = PgConnectOptions::from_str(&url).expect("valid database URL");
        let mut connection = options
            .connect()
            .await
            .expect("connect to the scenario database");
        let activated = sqlx::query(
            "UPDATE iam_openapi_specs SET status = 'active', activated_at = now() \
             WHERE id = $1::text::uuid AND status = 'draft'",
        )
        .bind(id)
        .execute(&mut connection)
        .await
        .expect("activate the version")
        .rows_affected();
        assert_eq!(activated, 1, "the remembered id names a draft version");
        connection.close().await.expect("close");
    }

    /// Bootstraps the first administrator of the scenario database as `service iam-bootstrap`
    /// does, for the user `user_id`, and remembers the id of its assignment for `{id}`, the id of
    /// the system role for `{role}` and the version of the assignment for the `If-Match` header. Scenarios that do not call it start without an
    /// administrator, so their policy versions and listings stay as they are.
    ///
    /// # Panics
    ///
    /// When the bootstrap fails or leaves no assignment.
    pub(crate) async fn bootstrap_administrator(&mut self, user_id: &str) {
        let config = self.config().await;
        let adapters = Adapters::connect(&config).await.expect("production wiring");
        let subject = SubjectRef::user(Uuid::parse(user_id).expect("a valid user id"));
        bootstrap_administrator(&adapters, subject)
            .await
            .expect("bootstrap the first administrator");
        let id = self
            .select_text(ADMINISTRATOR_ASSIGNMENT, user_id)
            .await
            .expect("the bootstrap left one assignment");
        self.remembered = Some(id);
        self.role = self
            .select_text(ADMINISTRATOR_ROLE, "iam-platform-admin")
            .await;
        self.if_match = Some("\"1\"".to_owned());
    }

    /// The text that the statement selects, with `value` bound to its only parameter, in the
    /// scenario database; `None` when it selects no row.
    pub(crate) async fn select_text(
        &mut self,
        statement: &'static str,
        value: &str,
    ) -> Option<String> {
        let url = self.database_url().await;
        let options = PgConnectOptions::from_str(&url).expect("valid database URL");
        let mut connection = options
            .connect()
            .await
            .expect("connect to the scenario database");
        let text = sqlx::query_scalar::<_, String>(statement)
            .bind(value.to_owned())
            .fetch_optional(&mut connection)
            .await
            .expect("select the text");
        connection.close().await.expect("close");
        text
    }

    /// The id of the role that a step seeded.
    ///
    /// # Panics
    ///
    /// When no step seeded a role.
    pub(crate) fn seeded_role(&self) -> &str {
        self.role.as_deref().expect("a step seeded a role")
    }

    /// Sets the page cursor that `{cursor}` stands for.
    pub(crate) fn set_cursor(&mut self, cursor: String) {
        self.cursor = Some(cursor);
    }

    /// The number the statement counts, with `value` bound to its only parameter, in the scenario
    /// database.
    pub(crate) async fn count(&mut self, statement: &'static str, value: &str) -> i64 {
        let url = self.database_url().await;
        let options = PgConnectOptions::from_str(&url).expect("valid database URL");
        let mut connection = options
            .connect()
            .await
            .expect("connect to the scenario database");
        let count = sqlx::query_scalar::<_, i64>(statement)
            .bind(value.to_owned())
            .fetch_one(&mut connection)
            .await
            .expect("count the rows");
        connection.close().await.expect("close");
        count
    }

    /// The name of the scenario's events topic.
    ///
    /// # Panics
    ///
    /// Before the scenario database, and with it the topic, exists.
    fn events_topic_name(&self) -> String {
        self.events_topic
            .clone()
            .expect("the scenario topic exists with the scenario database")
    }

    /// The committed records of the scenario's events topic, read once the relay has published
    /// every outbox row of the scenario database: the relay publishes after the commit.
    ///
    /// # Panics
    ///
    /// When the relay leaves a row unpublished for [`RELAY_DEADLINE`].
    pub(crate) async fn scenario_events(&mut self) -> Vec<EventRecord> {
        let started = tokio::time::Instant::now();
        while self.unpublished_rows().await > 0 {
            assert!(
                started.elapsed() < RELAY_DEADLINE,
                "the relay left outbox rows unpublished"
            );
            tokio::time::sleep(RELAY_POLL).await;
        }
        events_topic::read(&kafka_servers(), &self.events_topic_name()).await
    }

    /// The number of outbox rows of the scenario database that the relay has not published.
    async fn unpublished_rows(&mut self) -> i64 {
        let url = self.database_url().await;
        let options = PgConnectOptions::from_str(&url).expect("valid database URL");
        let mut connection = options
            .connect()
            .await
            .expect("connect to the scenario database");
        let rows = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM iam_outbox WHERE published_at IS NULL",
        )
        .fetch_one(&mut connection)
        .await
        .expect("count the unpublished rows");
        connection.close().await.expect("close");
        rows
    }

    /// The name of the scenario's events topic, created with the scenario database on first use.
    pub(crate) async fn scenario_topic_name(&mut self) -> String {
        self.database_url().await;
        self.events_topic_name()
    }

    /// The name of the state topic.
    pub(crate) fn state_topic() -> String {
        base_config().kafka.policy_topic
    }

    /// The names of the topics on the compose broker.
    pub(crate) async fn broker_topics() -> Vec<String> {
        events_topic::topics(&kafka_servers()).await
    }

    /// The topics that the outbox rows of the scenario database name, each once.
    pub(crate) async fn outbox_topics(&mut self) -> Vec<String> {
        let url = self.database_url().await;
        let options = PgConnectOptions::from_str(&url).expect("valid database URL");
        let mut connection = options
            .connect()
            .await
            .expect("connect to the scenario database");
        let topics =
            sqlx::query_scalar::<_, String>("SELECT DISTINCT topic FROM iam_outbox ORDER BY topic")
                .fetch_all(&mut connection)
                .await
                .expect("select the topics");
        connection.close().await.expect("close");
        topics
    }

    /// The subject token of the scenario; `None` before a step signed one.
    pub(crate) fn subject_token(&self) -> Option<&str> {
        self.subject_token.as_deref()
    }

    /// The replies of the scenario, oldest first.
    pub(crate) fn history(&self) -> &[Reply] {
        &self.history
    }

    /// The scenario's ephemeral signing key. The first call generates it and writes its public
    /// half to the key file that every later application instance of the scenario reads as
    /// `JWT_PUBLIC_KEYS_FILE`.
    pub(crate) fn signing_key(&mut self) -> &SigningKey {
        if self.signing.is_none() {
            let key = SigningKey::generate();
            let path = std::env::temp_dir().join(format!(
                "e2e-jwt-{}-{}.pem",
                std::process::id(),
                KEY_FILES.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::write(&path, key.public_pem()).expect("write the scenario key file");
            self.key_file = Some(path);
            self.signing = Some(key);
        }
        self.signing.as_ref().expect("generated above")
    }

    /// Makes the following requests carry the bearer token of the bootstrapped administrator.
    pub(crate) fn authenticate_as_administrator(&mut self) {
        self.caller_token = Some(self.signing_key().administrator_token());
    }

    /// Makes the following requests carry the bearer token of the administrator that holds
    /// `iam:route:core` and no other route key.
    pub(crate) fn authenticate_as_route_scoped_administrator(&mut self) {
        self.caller_token = Some(self.signing_key().route_scoped_administrator_token());
    }

    /// Makes the following requests carry the bearer token of the administrator that lacks
    /// `iam:grant:wildcard`.
    pub(crate) fn authenticate_as_restricted_administrator(&mut self) {
        self.caller_token = Some(self.signing_key().restricted_administrator_token());
    }

    /// Makes the following requests carry the bearer token of a valid service caller that holds
    /// no IAM key.
    pub(crate) fn authenticate_as_unprivileged_service(&mut self) {
        self.caller_token = Some(self.signing_key().unprivileged_caller_token());
    }

    /// Makes the following requests carry the bearer token of `service`, one of the scenario
    /// services of `SERVICE_CALLERS` that hold one validate key each.
    pub(crate) fn authenticate_as_service(&mut self, service: &str) {
        self.caller_token = Some(self.signing_key().service_token(service));
    }

    /// Makes the following requests carry a bearer token that no key file of the application
    /// holds the key of.
    pub(crate) fn authenticate_with_unknown_key(&mut self) {
        self.caller_token = Some(SigningKey::generate().administrator_token());
    }

    /// Sets the credential that `{token}` stands for.
    pub(crate) fn set_subject_token(&mut self, token: String) {
        self.subject_token = Some(token);
    }

    /// Records the revocation of `session` through the production wiring, as the revocation
    /// repository of the scenario database stores it.
    pub(crate) async fn revoke_session(&mut self, session: &str) {
        let config = self.config().await;
        let adapters = Adapters::connect(&config).await.expect("production wiring");
        let now = instant_after(Duration::ZERO);
        let revocation = SessionRevocation {
            id: SessionRevocationId::from_uuid(adapters.uuid_generator.generate()),
            session: SessionId::new(session).expect("a valid session id"),
            user: Uuid::parse(USER_ID).expect("a valid user id"),
            source: RevocationSource::Operator,
            revoked_by: ActorRef::System(SystemComponent::Bootstrap),
            revoked_at: now,
            prune_after: instant_after(REVOCATION_RETENTION),
        };
        adapters
            .revocations
            .revoke_session(&revocation)
            .await
            .expect("record the session revocation");
    }

    /// Creates the scenario database on first use and returns its URL.
    async fn database_url(&mut self) -> String {
        let options = server_options();
        if self.database.is_none() {
            let name = format!(
                "e2e_{}_{}",
                std::process::id(),
                DATABASES.fetch_add(1, Ordering::SeqCst)
            );
            let statement = format!("CREATE DATABASE \"{name}\"");
            sqlx::query(AssertSqlSafe(statement))
                .execute(&mut admin().await)
                .await
                .expect("create the scenario database");
            let mut connection = options.clone().database(&name).connect().await.unwrap();
            MIGRATOR.run(&mut connection).await.expect("migrate");
            connection.close().await.expect("close");
            let topic = events_topic::unique_name();
            events_topic::create(&kafka_servers(), &topic).await;
            self.events_topic = Some(topic);
            self.prepare(&name).await;
            self.database = Some(name);
        }
        url_with_database(self.database.as_deref().expect("created above"))
    }

    /// Prepares a new scenario database as `service serve` prepares its own: IAM's own
    /// specifications are registered and the supervisor of the per-replica tasks runs.
    async fn prepare(&mut self, database: &str) {
        let mut config = base_config();
        config.database.url = url_with_database(database);
        config.kafka.events_topic = self.events_topic_name();
        let adapters = Adapters::connect(&config).await.expect("production wiring");
        register_iam_specs(&adapters)
            .await
            .expect("register IAM's own specifications");
        let (stop, stopping) = watch::channel(false);
        let mut supervisor = start_tasks(&adapters, TaskMode::Test, stopping);
        self.rejected_attempts = Some(Arc::clone(&adapters.rejected_attempts));
        // A write returns after the Kafka acknowledgement of its policy version (Story 7.6), so
        // the relay runs for the scenario; maintenance and anti-entropy stay off, so versions and
        // counts stay as the scenarios expect.
        supervisor.spawn_singletons(
            singleton_set(&adapters)
                .into_iter()
                .filter(|singleton| {
                    matches!(singleton.name(), "outbox-relay" | "bulk-operation-runner")
                })
                .collect(),
        );
        self.tasks = Some((stop, supervisor));
    }

    /// Drops the scenario database and the scenario key file, if the scenario made them.
    pub(crate) async fn drop_database(&mut self) {
        if let Some((stop, supervisor)) = self.tasks.take() {
            stop.send_replace(true);
            supervisor.stop(TASK_STOP_GRACE).await;
        }
        if let Some(name) = self.database.take() {
            drop_named(&mut admin().await, &name).await;
        }
        if let Some(topic) = self.events_topic.take() {
            events_topic::delete(&kafka_servers(), &topic).await;
        }
        if let Some(path) = self.key_file.take() {
            drop(std::fs::remove_file(path));
        }
    }

    /// The configuration of an application instance on the scenario database.
    async fn config(&mut self) -> Config {
        let url = self.database_url().await;
        let mut config = base_config();
        config.database.url = url;
        config.kafka.events_topic = self.events_topic_name();
        if let Some(path) = &self.key_file {
            config.tokens.public_keys_file.clone_from(path);
        }
        config
    }

    /// Reads the IAM policy epoch of the scenario database through the production wiring.
    pub(crate) async fn policy_epoch(&mut self) -> PolicyEpoch {
        let config = self.config().await;
        let adapters = Adapters::connect(&config).await.expect("production wiring");
        adapters
            .policy_epochs
            .current()
            .await
            .expect("the policy epoch of the scenario database")
    }

    /// Builds a new application instance and sends one request to it.
    pub(crate) async fn send(
        &mut self,
        method: &str,
        path: &str,
        content_type: Option<&str>,
        body: &str,
    ) {
        let config = self.config().await;
        let mut adapters = Adapters::connect(&config).await.expect("production wiring");
        if let Some(buffer) = &self.rejected_attempts {
            adapters.rejected_attempts = Arc::clone(buffer);
        }
        adapters.policy_reads = Arc::new(AdministratorCallerPolicy::wrapping(Arc::clone(
            &adapters.policy_reads,
        )));
        for dependency in &self.failing {
            adapters = adapters.with_probe(Arc::new(StubProbe::failing(*dependency)));
        }
        let mut request = Request::builder().method(method).uri(self.substitute(path));
        if let Some(content_type) = content_type {
            request = request.header(header::CONTENT_TYPE, content_type);
        }
        if let Some(token) = &self.caller_token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(key) = &self.idempotency_key {
            request = request.header("idempotency-key", key);
        }
        if let Some(value) = &self.if_match {
            request = request.header(header::IF_MATCH, value);
        }
        if let Some(value) = &self.prefer {
            request = request.header("prefer", value);
        }
        let request = request
            .body(Body::from(self.substitute(body)))
            .expect("valid request");
        let response = router(adapters, &config)
            .expect("assembled router")
            .oneshot(request)
            .await
            .expect("infallible");
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let reply = Reply {
            status,
            headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        };
        self.record(&reply);
        self.history.push(reply.clone());
        self.reply = Some(reply);
    }

    /// Remembers the id of a created resource: a 201 body or a GraphQL mutation result.
    fn record(&mut self, reply: &Reply) {
        let json = reply.json();
        let created = if reply.status == 201 {
            json.get("id")
        } else {
            json.pointer("/data/createExampleApiResource/id")
                .or_else(|| json.pointer("/data/createRole/id"))
                .or_else(|| json.pointer("/data/createUpstream/id"))
                .or_else(|| json.pointer("/data/createRoute/id"))
                .or_else(|| json.pointer("/data/assignUserRole/id"))
        };
        if let Some(id) = created.and_then(Value::as_str) {
            self.created.push(id.to_owned());
            self.remembered = Some(id.to_owned());
        }
    }
}

/// The URL of database `name` on the server of `DATABASE_URL`: the path segment is replaced.
fn url_with_database(name: &str) -> String {
    let url = base_config().database.url;
    let (server, database) = url.rsplit_once('/').expect("a database name");
    let query = database
        .split_once('?')
        .map_or_else(String::new, |(_, query)| format!("?{query}"));
    format!("{server}/{name}{query}")
}
