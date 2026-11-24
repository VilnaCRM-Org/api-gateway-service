use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use health_check_domain::{Dependency, HealthProbe};
use health_check_infrastructure::CacheProbe;
use http_body_util::BodyExt as _;
use iam_application::{AntiEntropyCounters, AntiEntropyPorts, AntiEntropySettings, TopicAheadHold};
use iam_application::{
    GetChangeReceiptQuery, GetIdempotentReplayQuery, GetPolicyEpochQuery,
    GetPolicyEpochQueryHandler,
};
use iam_application::{MaintenanceSettings, OutboxRelayPorts, OutboxRelaySettings, SingletonLoop};
use iam_domain::{Credential, PolicyDigestValue, PolicyEpochRepository, TokenRejection};
use iam_infrastructure::BufferedRejectedAttemptLog;
use serde_json::Value;
use shared_domain::{EventBus, QueryBus};
use shared_infrastructure::bus::{InMemoryCommandBus, InMemoryQueryBus};
use some_module_application::{CreateExampleApiResourceHandler, GetExampleApiResourceHandler};
use some_module_domain::ExampleApiResourceRepository;
use test_support::access_token::{DEVELOPMENT_PUBLIC_KEYS_FILE, FakeAccessTokenVerifier};
use test_support::anti_entropy::{
    FakeAntiEntropyStore, FakePolicyLogTail, HashDigest, TextHeadCodec,
};
use test_support::bus::RecordingEventBus;
use test_support::cache::StubCache;
use test_support::change_receipt::{FakeChangeReceiptRepository, change_receipt};
use test_support::clock::FixedClock;
use test_support::graphql_permission::FakeGraphQlPermissionRepository;
use test_support::graphql_spec::FakeGraphQlSpecRepository;
use test_support::id::SequenceUuidGenerator;
use test_support::idempotency::{FakeIdempotencyRepository, idempotency_request};
use test_support::log::LogRecorder;
use test_support::maintenance_store::FakeMaintenanceStore;
use test_support::openapi_spec::FakeOpenApiSpecRepository;
use test_support::outbox_store::FakeOutboxStore;
use test_support::policy_epoch::{FakePolicyEpochRepository, seeded_policy_epoch};
use test_support::policy_log_producer::FakePolicyLogProducer;
use test_support::policy_read::FakePolicyReadRepository;
use test_support::probe::StubProbe;
use test_support::rate_policy::FakeRatePolicyRepository;
use test_support::repository::InMemoryExampleApiResourceRepository;
use test_support::request_digester::FakeRequestDigester;
use test_support::rest_permission::FakeRestPermissionRepository;
use test_support::revocation::FakeRevocationRepository;
use test_support::role::FakeRoleRepository;
use test_support::route::FakeRouteRepository;
use test_support::security_audit::FakeSecurityAuditLog;
use test_support::seed::TestRng;
use test_support::singleton_leadership::FakeSingletonLeadership;
use test_support::startup_lock::FakeStartupLock;
use test_support::task_state::FakeTaskStateRepository;
use test_support::token::FakeTokenRepository;
use test_support::topic_inspector::FakeTopicInspector;
use test_support::unit_of_work::FakeIamUnitOfWork;
use test_support::upstream::FakeUpstreamRepository;
use test_support::user_role::FakeUserRoleRepository;
use tokio::sync::{Notify, watch};
use tower::ServiceExt as _;

use super::{
    Adapters, AntiEntropyAdapters, BootstrapError, OutboxRelayAdapters, TaskMode,
    access_token_verifier, event_bus, register_change_queries, register_commands,
    register_iam_specs, register_queries, router, singleton_set, start_tasks,
};
use crate::cli::{KafkaArgs, ServeArgs};
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
    args.kafka = KafkaArgs {
        bootstrap_servers: Some("127.0.0.1:1".to_owned()),
        sasl_username: Some("iam-control".to_owned()),
        sasl_password: Some("unused".to_owned()),
        ..KafkaArgs::default()
    };
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
        rejected_attempts: Arc::new(BufferedRejectedAttemptLog::new()),
        startup_lock: Arc::new(FakeStartupLock::new()),
        singleton_leadership: Arc::new(FakeSingletonLeadership::leading()),
        maintenance_store: Arc::new(FakeMaintenanceStore::new()),
        task_states: Arc::new(FakeTaskStateRepository::new()),
        maintenance: MaintenanceSettings::default(),
        outbox_relay: None,
        change_receipts: Arc::new(FakeChangeReceiptRepository::new()),
        idempotency_records: Arc::new(FakeIdempotencyRepository::new()),
        roles: Arc::new(FakeRoleRepository::new()),
        upstreams: Arc::new(FakeUpstreamRepository::new()),
        routes: Arc::new(FakeRouteRepository::new()),
        rate_policies: Arc::new(FakeRatePolicyRepository::new()),
        unit_of_work: Arc::new(FakeIamUnitOfWork::new()),
        write_unit_of_work: Arc::new(FakeIamUnitOfWork::new()),
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

#[tokio::test]
async fn connect_wires_the_outbox_relay_and_its_listener_without_opening_a_connection() {
    let adapters = Adapters::connect(&config("test")).await.unwrap();

    let relay = adapters.outbox_relay.unwrap();

    assert_eq!(relay.settings, OutboxRelaySettings::default());
    assert!(!*relay.leading.borrow());
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

/// A policy repository in which the user of [`user_identity`] holds the reserved key
/// `iam:validate:*` and nothing else.
fn validating_caller() -> FakePolicyReadRepository {
    let role = iam_domain::RoleId::parse("00000000-0000-7000-8000-000000000102").unwrap();
    let grants = [(
        iam_domain::PermissionGrant::parse("iam:validate:*").unwrap(),
        iam_domain::GrantStatus::Active,
    )];
    let policy = iam_domain::SubjectPolicy::new(
        seeded_policy_epoch(),
        vec![iam_domain::RoleAssignment::new(
            role,
            iam_domain::AssignmentScope::Global,
            None,
        )],
        std::collections::BTreeMap::from([(role, iam_domain::CompiledRoleSet::compile(grants))]),
    );
    let subject = iam_domain::SubjectRef::user(
        shared_domain::Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap(),
    );
    FakePolicyReadRepository::new().with_subject(subject, policy)
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
    wiring.policy_reads = Arc::new(validating_caller());
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
async fn a_caller_without_the_reserved_validate_key_is_refused_token_resolution_with_403() {
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

    let refused = send(
        &app,
        resolution_request(Some("caller-token"), "subject-token"),
    )
    .await;

    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.json()["status"], 403);
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
    wiring.policy_reads = Arc::new(validating_caller());
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
async fn the_serve_mode_registers_the_singleton_set_with_the_maintenance_task() {
    let (stop, stopping) = watch::channel(false);

    let supervisor = start_tasks(&adapters(), TaskMode::Serve, stopping);

    assert_eq!(supervisor.len(), 2);
    let set = singleton_set(&adapters());
    assert_eq!(set.len(), 1);
    assert_eq!(set[0].name(), "policy-maintenance");
    stop.send_replace(true);
    assert_eq!(
        supervisor.stop(Duration::from_secs(1)).await,
        super::TaskStop::Drained
    );
}

/// Relay adapters over doubles and a pool that reaches no database.
fn relay_adapters() -> OutboxRelayAdapters {
    OutboxRelayAdapters {
        ports: OutboxRelayPorts {
            store: Arc::new(FakeOutboxStore::new()),
            producer: Arc::new(FakePolicyLogProducer::acknowledging()),
            inspector: Arc::new(FakeTopicInspector::passing()),
        },
        settings: OutboxRelaySettings::default(),
        listen_pool: sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://nobody:none@127.0.0.1:1/none")
            .unwrap(),
        wake: Arc::new(Notify::new()),
        leading: Arc::new(watch::channel(false).0),
        anti_entropy: None,
    }
}

#[tokio::test]
async fn the_serve_mode_adds_the_outbox_relay_and_its_listener() {
    let mut adapters = adapters();
    adapters.outbox_relay = Some(relay_adapters());
    let (stop, stopping) = watch::channel(false);

    let supervisor = start_tasks(&adapters, TaskMode::Serve, stopping);

    assert_eq!(supervisor.len(), 4);
    let names: Vec<_> = singleton_set(&adapters)
        .iter()
        .map(SingletonLoop::name)
        .collect();
    assert_eq!(names, ["policy-maintenance", "outbox-relay"]);
    stop.send_replace(true);
    assert_eq!(
        supervisor.stop(Duration::from_secs(1)).await,
        super::TaskStop::Drained
    );
}

#[tokio::test]
async fn the_serve_mode_adds_the_anti_entropy_task_after_the_relay_and_shares_its_hold() {
    let mut relay = relay_adapters();
    relay.anti_entropy = Some(AntiEntropyAdapters {
        ports: AntiEntropyPorts {
            store: Arc::new(FakeAntiEntropyStore::at(0, PolicyDigestValue::ZERO)),
            tail: Arc::new(FakePolicyLogTail::with(Vec::new())),
            task_states: Arc::new(FakeTaskStateRepository::new()),
            codec: Arc::new(TextHeadCodec),
            digest: Arc::new(HashDigest),
        },
        settings: AntiEntropySettings::default(),
        counters: Arc::new(AntiEntropyCounters::new()),
        hold: Arc::new(TopicAheadHold::new()),
    });
    let mut adapters = adapters();
    adapters.outbox_relay = Some(relay);

    let names: Vec<_> = singleton_set(&adapters)
        .iter()
        .map(SingletonLoop::name)
        .collect();

    assert_eq!(
        names,
        ["policy-maintenance", "outbox-relay", "anti-entropy"]
    );
}

#[test]
fn a_zero_maintenance_interval_registers_no_task() {
    let mut adapters = adapters();
    adapters.maintenance.interval = Duration::ZERO;

    assert!(singleton_set(&adapters).is_empty());
}

#[tokio::test]
async fn the_test_mode_starts_only_the_rejected_attempt_writer_and_stops_at_once() {
    let (stop, stopping) = watch::channel(false);

    let supervisor = start_tasks(&adapters(), TaskMode::Test, stopping);

    assert_eq!(supervisor.len(), 1);
    stop.send_replace(true);
    assert_eq!(
        supervisor.stop(Duration::from_secs(1)).await,
        super::TaskStop::Drained
    );
}

/// The access-validation operation through the assembled router over doubles: the matching of
/// concrete paths against the templates of the active version, the failing database and the
/// policy version that IAM has not issued.
mod access_validation {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use iam_domain::{
        AssignmentScope, CompiledRoleSet, GrantStatus, HttpMethod, PathTemplate, PermissionFlags,
        PermissionGrant, PolicyReadRepository, RepositoryError, RestOperation, RestOperationSet,
        RoleAssignment, RoleId, ServiceCatalog, ServiceName, SubjectPolicy, SubjectRef,
    };
    use serde_json::{Value, json};
    use test_support::policy_epoch::{FakePolicyEpochRepository, seeded_policy_epoch};
    use test_support::policy_read::FakePolicyReadRepository;
    use test_support::token::FakeTokenRepository;

    use super::{Answer, adapters, app, send, user_identity};

    const SUBJECT: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";

    fn operation(path: &str) -> RestOperation {
        RestOperation {
            method: HttpMethod::Get,
            template: PathTemplate::from_openapi_path(path).unwrap(),
            label: None,
            flags: PermissionFlags::NONE,
        }
    }

    /// The active version of `orders`: a templated operation and a literal one that wins over it.
    fn catalog() -> ServiceCatalog {
        let mut operations = RestOperationSet::new();
        operations.insert(operation("/api/orders/{id}")).unwrap();
        operations.insert(operation("/api/orders/latest")).unwrap();
        ServiceCatalog::new(
            ServiceName::new("orders").unwrap(),
            seeded_policy_epoch(),
            vec![operations],
            Vec::new(),
        )
    }

    /// A subject that holds the templated operation globally and the reserved key of the decision
    /// API (FR-4), which the caller needs to call it, and nothing else.
    fn holding_policy() -> FakePolicyReadRepository {
        let role = RoleId::parse("00000000-0000-7000-8000-000000000101").unwrap();
        let grants = [
            (
                PermissionGrant::parse("rest:orders:GET /api/orders/{}").unwrap(),
                GrantStatus::Active,
            ),
            (
                PermissionGrant::parse("iam:validate:*").unwrap(),
                GrantStatus::Active,
            ),
        ];
        let policy = SubjectPolicy::new(
            seeded_policy_epoch(),
            vec![RoleAssignment::new(role, AssignmentScope::Global, None)],
            BTreeMap::from([(role, CompiledRoleSet::compile(grants))]),
        );
        let subject = SubjectRef::user(shared_domain::Uuid::parse(SUBJECT).unwrap());
        FakePolicyReadRepository::new()
            .with_catalog(catalog())
            .with_subject(subject, policy)
    }

    /// Reads the policy of the first subject lookup from `inner` and fails every other read, so
    /// that the authorization of the caller passes and the decision path meets the failure.
    #[derive(Debug)]
    struct FailsAfterTheCaller {
        inner: FakePolicyReadRepository,
        subject_reads: AtomicUsize,
    }

    #[async_trait]
    impl PolicyReadRepository for FailsAfterTheCaller {
        async fn read_subject_policy(
            &self,
            subject: &SubjectRef,
        ) -> Result<SubjectPolicy, RepositoryError> {
            if self.subject_reads.fetch_add(1, Ordering::SeqCst) == 0 {
                self.inner.read_subject_policy(subject).await
            } else {
                Err(RepositoryError::Unavailable("policy read failed".into()))
            }
        }

        async fn read_service_catalog(
            &self,
            _service: &ServiceName,
        ) -> Result<Option<ServiceCatalog>, RepositoryError> {
            Err(RepositoryError::Unavailable("catalogue read failed".into()))
        }
    }

    fn wiring(
        policy: impl PolicyReadRepository + 'static,
        epochs: FakePolicyEpochRepository,
    ) -> Router {
        let tokens = FakeTokenRepository::new()
            .accepting(
                "caller-token",
                user_identity("caller-session", &["vilnacrm-api"]),
            )
            .accepting(
                "subject-token",
                user_identity("subject-session", &["vilnacrm-api"]),
            );
        let mut wired = adapters();
        wired.tokens = Arc::new(tokens);
        wired.policy_reads = Arc::new(policy);
        wired.policy_epochs = Arc::new(epochs);
        app(wired)
    }

    fn post(path: &str, bearer: Option<&str>, body: String) -> Request<Body> {
        let mut request = Request::post(path).header(header::CONTENT_TYPE, "application/json");
        if let Some(token) = bearer {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        request.body(Body::from(body)).unwrap()
    }

    fn rest(bearer: Option<&str>, target: &Value, minimum: Option<i64>) -> Request<Body> {
        let mut body = json!({
            "credential": "subject-token",
            "service": "orders",
            "requestId": "req-1"
        });
        for (name, value) in target.as_object().unwrap() {
            body[name] = value.clone();
        }
        if let Some(minimum) = minimum {
            body["minPolicyVersion"] = json!(minimum);
        }
        post("/api/access-validations", bearer, body.to_string())
    }

    fn get_order(path: &str) -> Value {
        json!({"rest": {"method": "GET", "path": path}})
    }

    async fn graphql(app: &Router, input: &str) -> Answer {
        let query = format!(
            "{{ validateAccess(input: {{credential: \"subject-token\", service: \"orders\", {input}, \
             requestId: \"req-1\"}}) {{ decision reason denied scopes {{ all }} }} }}"
        );
        let body = json!({ "query": query }).to_string();
        send(app, post("/api/graphql", Some("caller-token"), body)).await
    }

    #[tokio::test]
    async fn concrete_paths_are_matched_against_the_templates_of_the_active_version() {
        let app = wiring(holding_policy(), FakePolicyEpochRepository::new());
        let cases = [
            ("/api/orders/42", "allow", "allowed", json!([])),
            (
                "/api/orders/latest",
                "deny",
                "permission_missing",
                json!(["rest:orders:GET /api/orders/latest"]),
            ),
            (
                "/api/orders/42/items",
                "deny",
                "unknown_operation",
                json!([]),
            ),
            (
                "/api/orders/../42",
                "deny",
                "malformed_operation",
                json!([]),
            ),
        ];

        for (path, decision, reason, denied) in cases {
            let answer = send(&app, rest(Some("caller-token"), &get_order(path), None)).await;

            assert_eq!(answer.status, StatusCode::OK, "{path}");
            assert_eq!(answer.json()["decision"], decision, "{path}");
            assert_eq!(answer.json()["reason"], reason, "{path}");
            assert_eq!(answer.json()["denied"], denied, "{path}");
            assert_eq!(answer.json()["requestId"], "req-1", "{path}");
        }
    }

    #[tokio::test]
    async fn a_failing_database_is_a_200_deny_with_unavailable_over_rest_and_graphql() {
        // One application per interface: each request authorizes its caller with the first read.
        let failing = || {
            wiring(
                FailsAfterTheCaller {
                    inner: holding_policy(),
                    subject_reads: AtomicUsize::new(0),
                },
                FakePolicyEpochRepository::new(),
            )
        };

        let over_rest = send(
            &failing(),
            rest(Some("caller-token"), &get_order("/api/orders/42"), None),
        )
        .await;
        let over_graphql = graphql(
            &failing(),
            "rest: {method: \"GET\", path: \"/api/orders/42\"}",
        )
        .await;

        assert_eq!(over_rest.status, StatusCode::OK);
        assert_eq!(over_rest.json()["decision"], "deny");
        assert_eq!(over_rest.json()["reason"], "unavailable");
        assert_eq!(over_graphql.status, StatusCode::OK);
        assert_eq!(
            over_graphql.json()["data"]["validateAccess"]["reason"],
            "unavailable"
        );
    }

    #[tokio::test]
    async fn an_unreadable_policy_epoch_under_a_minimum_version_is_a_200_deny_with_unavailable() {
        let app = wiring(holding_policy(), FakePolicyEpochRepository::failing());

        let answer = send(
            &app,
            rest(Some("caller-token"), &get_order("/api/orders/42"), Some(1)),
        )
        .await;

        assert_eq!(answer.status, StatusCode::OK);
        assert_eq!(answer.json()["reason"], "unavailable");
    }

    #[tokio::test]
    async fn a_minimum_version_above_the_current_one_is_a_422_and_validation_failed() {
        let app = wiring(holding_policy(), FakePolicyEpochRepository::new());

        let over_rest = send(
            &app,
            rest(Some("caller-token"), &get_order("/api/orders/42"), Some(1)),
        )
        .await;
        let current = send(
            &app,
            rest(Some("caller-token"), &get_order("/api/orders/42"), Some(0)),
        )
        .await;
        let over_graphql = graphql(
            &app,
            "rest: {method: \"GET\", path: \"/api/orders/42\"}, minPolicyVersion: 1",
        )
        .await;

        assert_eq!(over_rest.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            over_rest.json()["violations"][0]["propertyPath"],
            "minPolicyVersion"
        );
        assert_eq!(current.status, StatusCode::OK);
        assert_eq!(
            over_graphql.json()["errors"][0]["extensions"]["code"],
            "VALIDATION_FAILED"
        );
    }

    fn batch_item(path: &str, request_id: &str) -> Value {
        json!({
            "credential": "subject-token", "service": "orders", "requestId": request_id,
            "rest": {"method": "GET", "path": path}
        })
    }

    /// The router over a token repository that the test keeps, so that it can count resolutions.
    fn counting_wiring() -> (Router, Arc<FakeTokenRepository>) {
        let tokens = Arc::new(
            FakeTokenRepository::new()
                .accepting(
                    "caller-token",
                    user_identity("caller-session", &["vilnacrm-api"]),
                )
                .accepting(
                    "subject-token",
                    user_identity("subject-session", &["vilnacrm-api"]),
                ),
        );
        let mut wired = adapters();
        wired.tokens = Arc::<FakeTokenRepository>::clone(&tokens);
        wired.policy_reads = Arc::new(holding_policy());
        (app(wired), tokens)
    }

    fn batch_request(checks: &[Value]) -> Request<Body> {
        post(
            "/api/access-validations/batch",
            Some("caller-token"),
            json!({ "checks": checks }).to_string(),
        )
    }

    #[tokio::test]
    async fn a_batch_is_decided_in_request_order() {
        let (app, _tokens) = counting_wiring();
        let checks = [
            batch_item("/api/orders/42", "first"),
            batch_item("/api/orders/latest", "second"),
            batch_item("/api/orders/../42", "third"),
        ];

        let answer = send(&app, batch_request(&checks)).await;

        assert_eq!(answer.status, StatusCode::OK);
        let results = answer.json()["results"].as_array().unwrap().clone();
        let reasons: Vec<&str> = results
            .iter()
            .map(|result| result["reason"].as_str().unwrap())
            .collect();
        assert_eq!(
            reasons,
            ["allowed", "permission_missing", "malformed_operation"]
        );
        assert_eq!(results[0]["requestId"], "first");
        assert_eq!(results[2]["requestId"], "third");
    }

    #[tokio::test]
    async fn a_batch_resolves_its_subject_token_once_however_many_checks_it_holds() {
        let (app, tokens) = counting_wiring();
        let one = [batch_item("/api/orders/42", "one")];
        let many: Vec<Value> = (0..50)
            .map(|index| batch_item("/api/orders/42", &index.to_string()))
            .collect();

        let before = tokens.calls();
        let _single = send(&app, batch_request(&one)).await;
        let single_calls = tokens.calls().saturating_sub(before);
        let before = tokens.calls();
        let answer = send(&app, batch_request(&many)).await;
        let many_calls = tokens.calls().saturating_sub(before);

        assert_eq!(answer.json()["results"].as_array().unwrap().len(), 50);
        assert!(single_calls >= 1);
        assert_eq!(many_calls, single_calls);
    }

    #[tokio::test]
    async fn a_batch_of_no_check_or_of_too_many_is_a_422_and_validation_failed() {
        let app = wiring(holding_policy(), FakePolicyEpochRepository::new());
        let many: Vec<Value> = (0..101)
            .map(|index| batch_item("/api/orders/42", &index.to_string()))
            .collect();

        for checks in [Vec::new(), many] {
            let body = json!({ "checks": checks });
            let over_rest = send(
                &app,
                post(
                    "/api/access-validations/batch",
                    Some("caller-token"),
                    body.to_string(),
                ),
            )
            .await;

            assert_eq!(over_rest.status, StatusCode::UNPROCESSABLE_ENTITY);
        }
        let inputs: Vec<String> = (0..101)
            .map(|index| {
                format!(
                    "{{credential: \"subject-token\", service: \"orders\", requestId: \"r{index}\", \
                     rest: {{method: \"GET\", path: \"/api/orders/42\"}}}}"
                )
            })
            .collect();
        let query = format!(
            "{{ validateAccessBatch(inputs: [{}]) {{ decision }} }}",
            inputs.join(",")
        );
        let over_graphql = send(
            &app,
            post(
                "/api/graphql",
                Some("caller-token"),
                json!({ "query": query }).to_string(),
            ),
        )
        .await;

        assert_eq!(
            over_graphql.json()["errors"][0]["extensions"]["code"],
            "VALIDATION_FAILED"
        );
    }

    #[tokio::test]
    async fn a_request_without_a_bearer_token_is_unauthenticated() {
        let app = wiring(holding_policy(), FakePolicyEpochRepository::new());

        let answer = send(&app, rest(None, &get_order("/api/orders/42"), None)).await;

        assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
        assert_eq!(answer.headers[header::WWW_AUTHENTICATE], "Bearer");
    }
}
