use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use health_check_domain::{Dependency, HealthProbe};
use health_check_infrastructure::CacheProbe;
use http_body_util::BodyExt as _;
use iam_application::{
    GetChangeReceiptQuery, GetIdempotentReplayQuery, GetPolicyEpochQuery,
    GetPolicyEpochQueryHandler,
};
use iam_domain::{Credential, PolicyEpochRepository, TokenRejection};
use serde_json::Value;
use shared_domain::{EventBus, QueryBus};
use shared_infrastructure::bus::{InMemoryCommandBus, InMemoryQueryBus};
use some_module_application::{CreateExampleApiResourceHandler, GetExampleApiResourceHandler};
use some_module_domain::ExampleApiResourceRepository;
use test_support::access_token::{DEVELOPMENT_PUBLIC_KEYS_FILE, FakeAccessTokenVerifier};
use test_support::bus::RecordingEventBus;
use test_support::cache::StubCache;
use test_support::change_receipt::{FakeChangeReceiptRepository, change_receipt};
use test_support::clock::FixedClock;
use test_support::graphql_permission::FakeGraphQlPermissionRepository;
use test_support::graphql_spec::FakeGraphQlSpecRepository;
use test_support::id::SequenceUuidGenerator;
use test_support::idempotency::{FakeIdempotencyRepository, idempotency_request};
use test_support::log::LogRecorder;
use test_support::openapi_spec::FakeOpenApiSpecRepository;
use test_support::policy_epoch::{FakePolicyEpochRepository, seeded_policy_epoch};
use test_support::policy_read::FakePolicyReadRepository;
use test_support::probe::StubProbe;
use test_support::repository::InMemoryExampleApiResourceRepository;
use test_support::request_digester::FakeRequestDigester;
use test_support::rest_permission::FakeRestPermissionRepository;
use test_support::revocation::FakeRevocationRepository;
use test_support::role::FakeRoleRepository;
use test_support::security_audit::FakeSecurityAuditLog;
use test_support::seed::TestRng;
use test_support::startup_lock::FakeStartupLock;
use test_support::token::FakeTokenRepository;
use test_support::unit_of_work::FakeIamUnitOfWork;
use test_support::user_role::FakeUserRoleRepository;
use tokio::sync::watch;
use tower::ServiceExt as _;

use super::{
    Adapters, BootstrapError, TaskMode, access_token_verifier, event_bus, register_change_queries,
    register_commands, register_iam_specs, register_queries, router, start_tasks,
};
use crate::cli::ServeArgs;
use crate::config::Config;

const FIRST_ID: &str = "00000000-0000-7000-8000-000000000001";

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap()
    }
}

fn config(app_env: &str) -> Config {
    let mut args = ServeArgs {
        app_env: Some(app_env.to_owned()),
        aws_region: Some("us-east-1".to_owned()),
        ..ServeArgs::default()
    };
    args.database.url = Some("postgres://app:unused@127.0.0.1:1/app".to_owned());
    args.tokens.public_keys_file = Some(DEVELOPMENT_PUBLIC_KEYS_FILE.to_owned());
    Config::from_args(args).unwrap()
}

fn healthy_probes() -> Vec<Arc<dyn HealthProbe>> {
    vec![
        Arc::new(StubProbe::healthy(Dependency::Database)),
        Arc::new(StubProbe::healthy(Dependency::Cache)),
        Arc::new(StubProbe::healthy(Dependency::MessageBroker)),
    ]
}

fn adapters() -> Adapters {
    Adapters {
        repository: Arc::new(InMemoryExampleApiResourceRepository::new()),
        policy_epochs: Arc::new(FakePolicyEpochRepository::new()),
        policy_reads: Arc::new(FakePolicyReadRepository::new()),
        security_audit_log: Arc::new(FakeSecurityAuditLog::new()),
        startup_lock: Arc::new(FakeStartupLock::new()),
        change_receipts: Arc::new(FakeChangeReceiptRepository::new()),
        idempotency_records: Arc::new(FakeIdempotencyRepository::new()),
        roles: Arc::new(FakeRoleRepository::new()),
        unit_of_work: Arc::new(FakeIamUnitOfWork::new()),
        request_digester: Arc::new(FakeRequestDigester),
        user_roles: Arc::new(FakeUserRoleRepository::new()),
        graphql_specs: Arc::new(FakeGraphQlSpecRepository::new()),
        openapi_specs: Arc::new(FakeOpenApiSpecRepository::new()),
        graphql_permissions: Arc::new(FakeGraphQlPermissionRepository::new()),
        rest_permissions: Arc::new(FakeRestPermissionRepository::new()),
        access_tokens: Arc::new(FakeAccessTokenVerifier::new()),
        tokens: Arc::new(FakeTokenRepository::new()),
        revocations: Arc::new(FakeRevocationRepository::new()),
        probes: healthy_probes(),
        event_bus: event_bus(),
        clock: Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        uuid_generator: Arc::new(SequenceUuidGenerator::starting_at(1)),
    }
}

fn app(adapters: Adapters) -> Router {
    router(adapters, &config("test")).unwrap()
}

async fn send(app: &Router, request: Request<Body>) -> Answer {
    let response = app.clone().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    Answer {
        status: parts.status,
        headers: parts.headers,
        body: String::from_utf8(bytes.to_vec()).unwrap(),
    }
}

fn get(path: &str) -> Request<Body> {
    Request::get(path).body(Body::empty()).unwrap()
}

fn post(path: &str, body: &str) -> Request<Body> {
    Request::post(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn create() -> Request<Body> {
    post(
        "/api/example_api_resources",
        r#"{"name":"Name","description":"Description"}"#,
    )
}

fn graphql(query: &str) -> Request<Body> {
    post(
        "/api/graphql",
        &serde_json::json!({ "query": query }).to_string(),
    )
}

#[tokio::test]
async fn every_handler_subscriber_and_probe_is_registered() {
    let app = app(adapters());

    let created = send(&app, create()).await;
    assert_eq!(created.status, StatusCode::CREATED);
    let id = created.json()["id"].as_str().unwrap().to_owned();
    let one = send(&app, get(&format!("/api/example_api_resources/{id}"))).await;
    assert_eq!(one.status, StatusCode::OK);
    assert_eq!(one.json()["name"], "Name");
    let list = send(&app, get("/api/example_api_resources")).await;
    assert_eq!(list.status, StatusCode::OK);
    assert_eq!(list.json().as_array().unwrap().len(), 1);

    let mutation = graphql(
        r#"mutation { createExampleApiResource(input: {name: "G", description: "D"}) { id name } }"#,
    );
    let query_one = graphql(&format!(
        r#"{{ exampleApiResource(id: "{id}") {{ id name }} }}"#
    ));
    let query_list = graphql("{ exampleApiResources { id name } }");
    for request in [mutation, query_one, query_list] {
        let answer = send(&app, request).await;
        assert_eq!(answer.status, StatusCode::OK);
        assert!(answer.json().get("errors").is_none(), "{}", answer.body);
    }

    let health = send(&app, get("/api/health")).await;
    assert_eq!(health.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn a_created_resource_is_audited_by_the_registered_subscriber() {
    let (recorder, _guard) = LogRecorder::install();
    let app = app(adapters());

    let created = send(&app, create()).await;

    assert_eq!(created.status, StatusCode::CREATED);
    let audit: Vec<_> = recorder
        .lines()
        .into_iter()
        .filter(|line| line.target == "audit")
        .collect();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].field("aggregate_id"), Some(FIRST_ID));
}

#[tokio::test]
async fn a_replaced_repository_serves_the_requests() {
    let mut adapters = adapters();
    adapters.repository = Arc::new(InMemoryExampleApiResourceRepository::failing());

    let answer = send(&app(adapters), create()).await;

    assert_eq!(answer.status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn a_replaced_probe_decides_the_health_answer() {
    let adapters = adapters().with_probe(Arc::new(StubProbe::failing(Dependency::Database)));

    let answer = send(&app(adapters), get("/api/health")).await;

    assert_eq!(answer.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        answer.body.contains("Database is not available"),
        "{}",
        answer.body
    );
    assert!(
        !answer.body.contains("Cache is not working"),
        "{}",
        answer.body
    );
}

#[tokio::test]
async fn a_failing_cache_behind_the_cache_probe_is_reported() {
    let cache_probe = CacheProbe::new(Arc::new(StubCache::failing()));
    let adapters = adapters().with_probe(Arc::new(cache_probe));

    let answer = send(&app(adapters), get("/api/health")).await;

    assert_eq!(answer.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        answer.body.contains("Cache is not working"),
        "{}",
        answer.body
    );
    assert!(
        !answer.body.contains("Database is not available"),
        "{}",
        answer.body
    );
}

#[tokio::test]
async fn a_replaced_event_bus_receives_the_event() {
    let recording = Arc::new(RecordingEventBus::new());
    let mut adapters = adapters();
    adapters.event_bus = {
        let port: Arc<dyn EventBus> = Arc::<RecordingEventBus>::clone(&recording);
        port
    };

    let answer = send(&app(adapters), create()).await;

    assert_eq!(answer.status, StatusCode::CREATED);
    let published = recording.published();
    assert_eq!(published.len(), 1);
    assert_eq!(published[0].aggregate_id.to_string(), FIRST_ID);
}

#[tokio::test]
async fn a_failing_event_bus_does_not_fail_the_create_request() {
    let mut adapters = adapters();
    adapters.event_bus = Arc::new(RecordingEventBus::failing());

    let answer = send(&app(adapters), create()).await;

    assert_eq!(answer.status, StatusCode::CREATED);
    assert_eq!(answer.json()["id"], FIRST_ID);
}

#[tokio::test]
async fn a_replaced_clock_stamps_the_event() {
    let (recorder, _guard) = LogRecorder::install();
    let moment = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(1_700_000_000))
        .unwrap();
    let mut adapters = adapters();
    adapters.clock = Arc::new(FixedClock::at(moment));

    let answer = send(&app(adapters), create()).await;

    assert_eq!(answer.status, StatusCode::CREATED);
    let lines = recorder.lines();
    let audit = lines.iter().find(|line| line.target == "audit").unwrap();
    assert_eq!(
        audit.field("occurred_at"),
        Some("2023-11-14T22:13:20.000000Z")
    );
}

#[tokio::test]
async fn a_replaced_uuid_generator_chooses_the_identifier() {
    let mut adapters = adapters();
    adapters.uuid_generator = Arc::new(SequenceUuidGenerator::starting_at(42));

    let answer = send(&app(adapters), create()).await;

    assert_eq!(answer.status, StatusCode::CREATED);
    assert_eq!(answer.json()["id"], "00000000-0000-7000-8000-00000000002a");
    assert_eq!(
        answer.headers[header::LOCATION],
        "/api/example_api_resources/00000000-0000-7000-8000-00000000002a"
    );
}

#[tokio::test]
async fn with_probe_keeps_the_order_and_the_other_probes() {
    let adapters = adapters().with_probe(Arc::new(StubProbe::failing(Dependency::Cache)));

    let dependencies: Vec<_> = adapters
        .probes
        .iter()
        .map(|probe| probe.dependency())
        .collect();
    assert_eq!(
        dependencies,
        [
            Dependency::Database,
            Dependency::Cache,
            Dependency::MessageBroker
        ]
    );
    let outcomes: Vec<_> = {
        let mut outcomes = Vec::new();
        for probe in &adapters.probes {
            outcomes.push(probe.check().await.is_ok());
        }
        outcomes
    };
    assert_eq!(outcomes, [true, false, true]);
}

fn create_handler(
    repository: &Arc<dyn ExampleApiResourceRepository>,
) -> CreateExampleApiResourceHandler {
    CreateExampleApiResourceHandler::new(
        Arc::clone(repository),
        event_bus(),
        Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    )
}

fn repository() -> Arc<dyn ExampleApiResourceRepository> {
    Arc::new(InMemoryExampleApiResourceRepository::new())
}

fn policy_epochs() -> Arc<dyn PolicyEpochRepository> {
    Arc::new(FakePolicyEpochRepository::new())
}

#[test]
fn a_second_command_handler_is_a_duplicate_that_names_the_message() {
    let repository = repository();
    let bus = register_commands(InMemoryCommandBus::new(), create_handler(&repository)).unwrap();

    let error = register_commands(bus, create_handler(&repository)).unwrap_err();

    assert!(
        matches!(error, BootstrapError::DuplicateHandler(_)),
        "{error:?}"
    );
    assert!(
        error.to_string().contains("CreateExampleApiResource"),
        "{error}"
    );
}

#[test]
fn a_second_query_handler_is_a_duplicate_that_names_the_message() {
    let repository = repository();
    let bus = InMemoryQueryBus::new()
        .register(GetExampleApiResourceHandler::new(Arc::clone(&repository)))
        .unwrap();

    let error = register_queries(bus, &repository, &policy_epochs()).unwrap_err();

    assert!(
        matches!(error, BootstrapError::DuplicateHandler(_)),
        "{error:?}"
    );
    assert!(
        error.to_string().contains("GetExampleApiResource"),
        "{error}"
    );
}

#[test]
fn a_second_policy_epoch_query_handler_is_a_duplicate_that_names_the_message() {
    let bus = InMemoryQueryBus::new()
        .register(GetPolicyEpochQueryHandler::new(policy_epochs()))
        .unwrap();

    let error = register_queries(bus, &repository(), &policy_epochs()).unwrap_err();

    assert!(
        matches!(error, BootstrapError::DuplicateHandler(_)),
        "{error:?}"
    );
    assert!(error.to_string().contains("GetPolicyEpochQuery"), "{error}");
}

#[tokio::test]
async fn the_query_bus_answers_the_policy_epoch_query_from_the_iam_adapter() {
    let bus = register_queries(InMemoryQueryBus::new(), &repository(), &policy_epochs()).unwrap();
    let queries: Arc<dyn QueryBus> = Arc::new(bus);

    let epoch = queries.ask(GetPolicyEpochQuery).await.unwrap();

    assert_eq!(epoch, seeded_policy_epoch());
}

#[test]
fn the_database_error_keeps_its_message_and_source() {
    let source = sqlx::Error::Configuration("bad url".into());

    let error = BootstrapError::from(source);

    assert_eq!(error.to_string(), "invalid database settings");
    assert!(std::error::Error::source(&error).is_some());
}

fn change_queries(
    bus: InMemoryQueryBus,
    adapters: &Adapters,
) -> Result<InMemoryQueryBus, BootstrapError> {
    register_change_queries(
        bus,
        &adapters.change_receipts,
        &adapters.idempotency_records,
        &adapters.clock,
    )
}

#[tokio::test]
async fn the_query_bus_answers_the_change_receipt_and_replay_queries_from_the_iam_adapters() {
    let mut rng = TestRng::from_env();
    let receipt = change_receipt(&mut rng);
    let mut adapters = adapters();
    adapters.change_receipts =
        Arc::new(FakeChangeReceiptRepository::holding(vec![receipt.clone()]));
    let bus = change_queries(InMemoryQueryBus::new(), &adapters).unwrap();
    let queries: Arc<dyn QueryBus> = Arc::new(bus);

    let found = queries
        .ask(GetChangeReceiptQuery {
            change_id: receipt.change_id(),
        })
        .await
        .unwrap();
    let replay = queries
        .ask(GetIdempotentReplayQuery {
            actor: receipt.actor().clone(),
            request: idempotency_request(&mut rng),
        })
        .await
        .unwrap();

    assert_eq!(found, receipt);
    assert_eq!(replay, None);
}

#[test]
fn a_second_change_receipt_handler_is_a_duplicate_that_names_the_query() {
    let adapters = adapters();
    let bus = change_queries(InMemoryQueryBus::new(), &adapters).unwrap();

    let error = change_queries(bus, &adapters).unwrap_err();

    assert!(
        matches!(error, BootstrapError::DuplicateHandler(_)),
        "{error:?}"
    );
    assert!(
        error.to_string().contains("GetChangeReceiptQuery"),
        "{error}"
    );
}

fn verify(adapters: &Adapters, raw: &str) -> Result<iam_domain::AccessToken, TokenRejection> {
    adapters
        .access_tokens
        .verify(&Credential::new(raw.to_owned()))
}

/// A configuration whose key file is a copy of the development key file that the test may change.
fn config_with_own_key_file(name: &str) -> (Config, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!(
        "service-bootstrap-{}-{name}.pem",
        std::process::id()
    ));
    std::fs::copy(DEVELOPMENT_PUBLIC_KEYS_FILE, &path).unwrap();
    let mut config = config("test");
    config.tokens.public_keys_file.clone_from(&path);
    (config, path)
}

#[tokio::test]
async fn connect_wires_the_jwt_verifier_of_the_configured_key_file() {
    let adapters = Adapters::connect(&config("test")).await.unwrap();

    assert_eq!(verify(&adapters, " "), Err(TokenRejection::Missing));
    assert_eq!(verify(&adapters, "a.b.c"), Err(TokenRejection::Invalid));
}

#[test]
fn the_jwt_verifier_checks_tokens_against_the_injected_clock_and_settings() {
    let clock = Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH));

    let verifier = access_token_verifier(&config("test"), clock).unwrap();

    assert_eq!(
        verifier.verify(&Credential::new(String::new())),
        Err(TokenRejection::Missing)
    );
    assert_eq!(
        verifier.verify(&Credential::new("not-a-token".to_owned())),
        Err(TokenRejection::Invalid)
    );
}

#[tokio::test]
async fn connect_refuses_a_key_file_that_no_longer_holds_a_key_set() {
    let (config, path) = config_with_own_key_file("emptied");
    std::fs::write(&path, "").unwrap();

    let error = Adapters::connect(&config).await.unwrap_err();

    assert!(matches!(error, BootstrapError::KeyFile(_)), "{error:?}");
    assert_eq!(error.to_string(), "invalid JWT_PUBLIC_KEYS_FILE");
    assert!(std::error::Error::source(&error).is_some());
}

#[test]
fn the_key_file_is_polled_every_five_seconds() {
    assert_eq!(super::KEY_FILE_POLL_INTERVAL, Duration::from_secs(5));
}

#[tokio::test]
async fn connect_wires_a_token_repository_that_refuses_before_reading_the_revocation_state() {
    let adapters = Adapters::connect(&config("test")).await.unwrap();

    for (raw, rejection) in [
        (" ", TokenRejection::Missing),
        ("a.b.c", TokenRejection::Invalid),
        ("a.b.c", TokenRejection::Invalid),
    ] {
        let outcome = adapters
            .tokens
            .resolve(&Credential::new(raw.to_owned()))
            .await;
        assert_eq!(outcome, Err(rejection));
    }
}

fn user_identity(session: &str, audiences: &[&str]) -> iam_domain::TokenIdentity {
    iam_domain::TokenIdentity::from(
        &iam_domain::AccessToken::new(iam_domain::AccessTokenParts {
            subject: iam_domain::SubjectId::User(
                shared_domain::Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap(),
            ),
            session: Some(iam_domain::SessionId::new(session).unwrap()),
            token_id: iam_domain::TokenId::new("jti-1").unwrap(),
            roles: vec!["ROLE_USER".to_owned()],
            issued_at: SystemTime::UNIX_EPOCH,
            expires_at: SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(600))
                .unwrap(),
        })
        .with_audiences(audiences.iter().map(|&value| value.to_owned()).collect()),
    )
}

fn resolution_request(bearer: Option<&str>, credential: &str) -> Request<Body> {
    let mut request =
        Request::post("/api/token-resolutions").header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = bearer {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    request
        .body(Body::from(format!(r#"{{"credential":"{credential}"}}"#)))
        .unwrap()
}

#[tokio::test]
async fn the_token_resolution_operation_is_registered_behind_the_caller_authentication() {
    let tokens = FakeTokenRepository::new()
        .accepting(
            "caller-token",
            user_identity("caller-session", &["vilnacrm-api"]),
        )
        .accepting(
            "subject-token",
            user_identity("subject-session", &["vilnacrm-api"]),
        )
        .rejecting("expired-token", TokenRejection::Expired);
    let mut wiring = adapters();
    wiring.tokens = Arc::new(tokens);
    let app = app(wiring);

    let resolved = send(
        &app,
        resolution_request(Some("caller-token"), "subject-token"),
    )
    .await;
    let expired = send(
        &app,
        resolution_request(Some("caller-token"), "expired-token"),
    )
    .await;
    let anonymous = send(&app, resolution_request(None, "subject-token")).await;

    assert_eq!(resolved.status, StatusCode::OK);
    assert_eq!(resolved.json()["resolved"], true);
    assert_eq!(resolved.json()["sessionId"], "subject-session");
    assert_eq!(expired.status, StatusCode::OK);
    assert_eq!(expired.json()["reason"], "token_expired");
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    assert_eq!(anonymous.headers[header::WWW_AUTHENTICATE], "Bearer");
}

#[tokio::test]
async fn the_resolve_token_query_reaches_the_iam_state_of_the_assembled_schema() {
    let tokens = FakeTokenRepository::new()
        .accepting(
            "caller-token",
            user_identity("caller-session", &["vilnacrm-api"]),
        )
        .accepting(
            "subject-token",
            user_identity("subject-session", &["vilnacrm-api"]),
        );
    let mut wiring = adapters();
    wiring.tokens = Arc::new(tokens);
    let app = app(wiring);
    let query = serde_json::json!({
        "query": r#"{ resolveToken(input: {credential: "subject-token"}) { resolved sessionId } }"#
    })
    .to_string();
    let request = |bearer: Option<&str>| {
        let mut request =
            Request::post("/api/graphql").header(header::CONTENT_TYPE, "application/json");
        if let Some(token) = bearer {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        request.body(Body::from(query.clone())).unwrap()
    };

    let authenticated = send(&app, request(Some("caller-token"))).await;
    let anonymous = send(&app, request(None)).await;

    assert_eq!(
        authenticated.json()["data"]["resolveToken"],
        serde_json::json!({ "resolved": true, "sessionId": "subject-session" })
    );
    assert_eq!(
        anonymous.json()["errors"][0]["extensions"]["code"],
        "UNAUTHENTICATED"
    );
}

#[tokio::test]
async fn the_registration_holds_the_startup_lock_and_releases_it_when_it_ends() {
    let lock = Arc::new(FakeStartupLock::new());
    let mut adapters = adapters();
    let port: Arc<FakeStartupLock> = Arc::clone(&lock);
    adapters.startup_lock = port;

    // The doubles share no state, so the activation of the loaded draft finds nothing: the
    // outcome is the registration failure, and the lock must be released all the same.
    let outcome = register_iam_specs(&adapters).await;

    assert!(matches!(outcome, Err(BootstrapError::Registration(_))));
    assert_eq!(lock.taken(), [iam_domain::OWN_SPECIFICATIONS_LOCK]);
    assert_eq!(lock.held(), Vec::<String>::new());
}

#[tokio::test]
async fn a_lock_that_cannot_be_taken_fails_the_registration_before_anything_is_written() {
    let mut adapters = adapters();
    adapters.startup_lock = Arc::new(FakeStartupLock::failing());

    let outcome = register_iam_specs(&adapters).await;

    assert!(matches!(outcome, Err(BootstrapError::Lock(_))));
}

#[tokio::test]
async fn the_supervisor_starts_without_a_task_and_stops_at_once() {
    let (stop, stopping) = watch::channel(false);

    let supervisor = start_tasks(&adapters(), TaskMode::Test, stopping);

    assert!(supervisor.is_empty());
    stop.send_replace(true);
    assert_eq!(
        supervisor.stop(Duration::from_secs(1)).await,
        super::TaskStop::Drained
    );
}
