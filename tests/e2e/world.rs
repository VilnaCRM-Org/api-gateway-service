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
    ActorRef, PolicyEpoch, RevocationSource, SessionId, SessionRevocation, SessionRevocationId,
    SystemComponent,
};
use serde_json::Value;
use service::bootstrap::{Adapters, router};
use service::cli::{Cli, Command};
use service::config::Config;
use shared_domain::Uuid;
use shared_infrastructure::persistence::MIGRATOR;
use sqlx::postgres::PgConnectOptions;
use sqlx::{AssertSqlSafe, ConnectOptions as _, Connection as _, PgConnection};
use test_support::probe::StubProbe;
use tower::ServiceExt as _;

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

/// How long a session revocation recorded by a step is kept before it may be pruned.
const REVOCATION_RETENTION: Duration = Duration::from_hours(24);

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
    cursor: Option<String>,
    role: Option<String>,
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

    /// Makes the following requests carry this `If-Match` header.
    pub(crate) fn set_if_match(&mut self, value: String) {
        self.if_match = Some(value);
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

    /// Makes the following requests carry the bearer token of a valid service caller.
    pub(crate) fn authenticate_as_service(&mut self) {
        self.caller_token = Some(self.signing_key().caller_token());
    }

    /// Makes the following requests carry a bearer token that no key file of the application
    /// holds the key of.
    pub(crate) fn authenticate_with_unknown_key(&mut self) {
        self.caller_token = Some(SigningKey::generate().caller_token());
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
            self.database = Some(name);
        }
        url_with_database(self.database.as_deref().expect("created above"))
    }

    /// Drops the scenario database and the scenario key file, if the scenario made them.
    pub(crate) async fn drop_database(&mut self) {
        if let Some(name) = self.database.take() {
            drop_named(&mut admin().await, &name).await;
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
