use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use health_check_domain::{Dependency, HealthProbe};
use http_body_util::BodyExt as _;
use iam_application::MaintenanceSettings;
use iam_domain::{BulkChunker, BulkPacing};
use iam_infrastructure::BufferedRejectedAttemptLog;
use serde_json::Value;
use test_support::access_token::{DEVELOPMENT_PUBLIC_KEYS_FILE, FakeAccessTokenVerifier};
use test_support::anti_entropy::FakePolicyLogTail;
use test_support::bulk_operation::{FakeBulkOperationRepository, FakeBulkRoleTargetStore};
use test_support::change_receipt::FakeChangeReceiptRepository;
use test_support::clock::FixedClock;
use test_support::graphql_permission::FakeGraphQlPermissionRepository;
use test_support::graphql_spec::FakeGraphQlSpecRepository;
use test_support::id::SequenceUuidGenerator;
use test_support::idempotency::FakeIdempotencyRepository;
use test_support::maintenance_store::FakeMaintenanceStore;
use test_support::openapi_spec::FakeOpenApiSpecRepository;
use test_support::policy_epoch::FakePolicyEpochRepository;
use test_support::policy_read::FakePolicyReadRepository;
use test_support::policy_state_inventory::FakePolicyStateInventory;
use test_support::probe::StubProbe;
use test_support::rate_policy::FakeRatePolicyRepository;
use test_support::repository::InMemoryExampleApiResourceRepository;
use test_support::request_digester::FakeRequestDigester;
use test_support::rest_permission::FakeRestPermissionRepository;
use test_support::revocation::FakeRevocationRepository;
use test_support::role::FakeRoleRepository;
use test_support::route::FakeRouteRepository;
use test_support::security_audit::FakeSecurityAuditLog;
use test_support::singleton_leadership::FakeSingletonLeadership;
use test_support::startup_lock::FakeStartupLock;
use test_support::task_state::FakeTaskStateRepository;
use test_support::token::FakeTokenRepository;
use test_support::token_lifetime_floor::FakeTokenLifetimeFloor;
use test_support::unit_of_work::FakeIamUnitOfWork;
use test_support::upstream::FakeUpstreamRepository;
use test_support::user_role::FakeUserRoleRepository;

use crate::bootstrap::{Adapters, event_bus, router};
use crate::cli::{KafkaArgs, ServeArgs};
use crate::config::{BulkSettings, Config};
use crate::graphql::handler::EXPLORER_CONTENT_SECURITY_POLICY;
use crate::http::docs::DOCS_CONTENT_SECURITY_POLICY;
use crate::http::security_headers::DEFAULT_CONTENT_SECURITY_POLICY;
use tower::ServiceExt as _;

const MISSING_ID: &str = "00000000-0000-7000-8000-0000000000ff";

/// Method, path, body, expected status and expected content security policy.
type Route<'a> = (Method, String, Option<&'a str>, StatusCode, &'a str);

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
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

fn adapters() -> Adapters {
    let probes: Vec<Arc<dyn HealthProbe>> = vec![
        Arc::new(StubProbe::healthy(Dependency::Database)),
        Arc::new(StubProbe::healthy(Dependency::Cache)),
        Arc::new(StubProbe::healthy(Dependency::MessageBroker)),
    ];
    Adapters {
        repository: Arc::new(InMemoryExampleApiResourceRepository::new()),
        policy_epochs: Arc::new(FakePolicyEpochRepository::new()),
        policy_reads: Arc::new(FakePolicyReadRepository::new()),
        bulk_operations: Arc::new(FakeBulkOperationRepository::new()),
        bulk_targets: Arc::new(FakeBulkRoleTargetStore::new()),
        bulk: BulkSettings {
            chunker: BulkChunker::new(1_000).unwrap(),
            pacing: BulkPacing::new(2_000).unwrap(),
        },
        policy_inventory: Arc::new(FakePolicyStateInventory::new()),
        policy_tail: Arc::new(FakePolicyLogTail::with(Vec::new())),
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
        token_lifetime_floor: Arc::new(FakeTokenLifetimeFloor::new()),
        max_token_lifetime: Duration::from_mins(15),
        probes,
        event_bus: event_bus(),
        clock: Arc::new(FixedClock::at(std::time::SystemTime::UNIX_EPOCH)),
        uuid_generator: Arc::new(SequenceUuidGenerator::starting_at(1)),
    }
}

async fn send_to(app: &Router, request: Request<Body>) -> Answer {
    let response = app.clone().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    Answer {
        status: parts.status,
        headers: parts.headers,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

async fn send(app_env: &str, request: Request<Body>) -> Answer {
    let app = router(adapters(), &config(app_env)).unwrap();
    send_to(&app, request).await
}

fn request(method: Method, path: &str, body: Option<&str>) -> Request<Body> {
    let builder = Request::builder().method(method).uri(path);
    match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

fn assert_common_headers(answer: &Answer, policy: &str, route: &str) {
    assert!(answer.headers.contains_key("x-request-id"), "{route}");
    assert_eq!(
        answer.headers["x-content-type-options"], "nosniff",
        "{route}"
    );
    assert_eq!(answer.headers["x-frame-options"], "DENY", "{route}");
    assert_eq!(answer.headers["referrer-policy"], "no-referrer", "{route}");
    assert_eq!(answer.headers["content-security-policy"], policy, "{route}");
}

#[tokio::test]
async fn every_route_carries_the_request_id_and_the_security_headers() {
    let graphql = r#"{"query":"{ exampleApiResources { id } }"}"#;
    let create = r#"{"name":"Name","description":"Description"}"#;
    let resource = format!("/api/example_api_resources/{MISSING_ID}");
    let routes: Vec<Route<'_>> = vec![
        (
            Method::POST,
            "/api/example_api_resources".into(),
            Some(create),
            StatusCode::CREATED,
            DEFAULT_CONTENT_SECURITY_POLICY,
        ),
        (
            Method::GET,
            resource,
            None,
            StatusCode::NOT_FOUND,
            DEFAULT_CONTENT_SECURITY_POLICY,
        ),
        (
            Method::GET,
            "/api/example_api_resources".into(),
            None,
            StatusCode::OK,
            DEFAULT_CONTENT_SECURITY_POLICY,
        ),
        (
            Method::POST,
            "/api/graphql".into(),
            Some(graphql),
            StatusCode::OK,
            DEFAULT_CONTENT_SECURITY_POLICY,
        ),
        (
            Method::GET,
            "/api/graphql".into(),
            None,
            StatusCode::OK,
            EXPLORER_CONTENT_SECURITY_POLICY,
        ),
        (
            Method::GET,
            "/api/health".into(),
            None,
            StatusCode::NO_CONTENT,
            DEFAULT_CONTENT_SECURITY_POLICY,
        ),
        (
            Method::GET,
            "/ping".into(),
            None,
            StatusCode::OK,
            DEFAULT_CONTENT_SECURITY_POLICY,
        ),
        (
            Method::GET,
            "/api/docs".into(),
            None,
            StatusCode::OK,
            DOCS_CONTENT_SECURITY_POLICY,
        ),
        (
            Method::GET,
            "/api/docs/openapi.json".into(),
            None,
            StatusCode::OK,
            DEFAULT_CONTENT_SECURITY_POLICY,
        ),
        (
            Method::GET,
            "/api/docs/swagger-ui.css".into(),
            None,
            StatusCode::OK,
            DEFAULT_CONTENT_SECURITY_POLICY,
        ),
        (
            Method::GET,
            "/api/docs/missing.js".into(),
            None,
            StatusCode::NOT_FOUND,
            DEFAULT_CONTENT_SECURITY_POLICY,
        ),
        (
            Method::GET,
            "/api/docs/%FF".into(),
            None,
            StatusCode::BAD_REQUEST,
            DEFAULT_CONTENT_SECURITY_POLICY,
        ),
        (
            Method::GET,
            "/api/unknown".into(),
            None,
            StatusCode::NOT_FOUND,
            DEFAULT_CONTENT_SECURITY_POLICY,
        ),
        (
            Method::DELETE,
            "/api/example_api_resources".into(),
            None,
            StatusCode::METHOD_NOT_ALLOWED,
            DEFAULT_CONTENT_SECURITY_POLICY,
        ),
    ];
    let app = router(adapters(), &config("dev")).unwrap();
    for (method, path, body, status, policy) in routes {
        let route = format!("{method} {path}");
        let answer = send_to(&app, request(method, &path, body)).await;
        assert_eq!(answer.status, status, "{route}: {}", answer.body);
        assert_common_headers(&answer, policy, &route);
    }
}

#[tokio::test]
async fn an_unknown_route_is_the_404_problem() {
    let answer = send("test", request(Method::GET, "/api/unknown", None)).await;

    assert_eq!(answer.status, StatusCode::NOT_FOUND);
    assert_eq!(
        answer.headers[header::CONTENT_TYPE],
        "application/problem+json"
    );
    let body: Value = serde_json::from_str(&answer.body).unwrap();
    assert_eq!(body["status"], 404);
    assert_eq!(body["detail"], "No route matches the request path.");
}

#[tokio::test]
async fn a_wrong_method_is_the_405_problem_with_the_allowed_methods() {
    let answer = send(
        "test",
        request(Method::DELETE, "/api/example_api_resources", None),
    )
    .await;

    assert_eq!(answer.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        answer.headers[header::CONTENT_TYPE],
        "application/problem+json"
    );
    let mut allowed: Vec<_> = answer.headers[header::ALLOW]
        .to_str()
        .unwrap()
        .split(',')
        .map(str::trim)
        .collect();
    allowed.sort_unstable();
    assert_eq!(allowed, ["GET", "HEAD", "POST"]);
    let body: Value = serde_json::from_str(&answer.body).unwrap();
    assert_eq!(body["status"], 405);
}

#[tokio::test]
async fn a_panicking_probe_is_the_bare_500_problem() {
    let adapters = adapters().with_probe(Arc::new(StubProbe::panicking(Dependency::Database)));
    let app = router(adapters, &config("test")).unwrap();

    let answer = send_to(&app, request(Method::GET, "/api/health", None)).await;

    assert_eq!(answer.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        answer.headers[header::CONTENT_TYPE],
        "application/problem+json"
    );
    assert_eq!(
        answer.body,
        r#"{"type":"about:blank","title":"Internal Server Error","status":500}"#
    );
    assert_common_headers(&answer, DEFAULT_CONTENT_SECURITY_POLICY, "panic");
}

#[tokio::test]
async fn a_body_over_the_limit_is_the_413_problem() {
    let mut config = config("test");
    config.max_body_bytes = 1024;
    let app = router(adapters(), &config).unwrap();
    let body = format!(r#"{{"name":"{}","description":"d"}}"#, "x".repeat(2048));

    let answer = send_to(
        &app,
        request(Method::POST, "/api/example_api_resources", Some(&body)),
    )
    .await;

    assert_eq!(answer.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        answer.headers[header::CONTENT_TYPE],
        "application/problem+json"
    );
    assert_common_headers(&answer, DEFAULT_CONTENT_SECURITY_POLICY, "413");
}

#[tokio::test]
async fn a_graphql_body_is_read_up_to_the_limit_of_its_route() {
    let mut config = config("test");
    config.max_body_bytes = 1024;
    let app = router(adapters(), &config).unwrap();
    let query = |padding: usize| {
        format!(
            r#"{{"query":"{{ __typename }}","variables":{{"padding":"{}"}}}}"#,
            "x".repeat(padding)
        )
    };

    let read = send_to(
        &app,
        request(Method::POST, "/api/graphql", Some(&query(2048))),
    )
    .await;
    let refused = send_to(
        &app,
        request(
            Method::POST,
            "/api/graphql",
            Some(&query(super::GRAPHQL_BODY_LIMIT_BYTES)),
        ),
    )
    .await;

    assert_ne!(read.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(refused.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test(start_paused = true)]
async fn a_request_over_its_budget_is_the_503_problem() {
    let mut config = config("test");
    config.request_timeout = Duration::from_secs(1);
    config.health_probe_timeout = Duration::from_secs(60);
    let adapters = adapters().with_probe(Arc::new(StubProbe::hanging(Dependency::Database)));
    let app = router(adapters, &config).unwrap();

    let answer = send_to(&app, request(Method::GET, "/api/health", None)).await;

    assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        answer.headers[header::CONTENT_TYPE],
        "application/problem+json"
    );
    let body: Value = serde_json::from_str(&answer.body).unwrap();
    assert_eq!(body["detail"], "The request exceeded its time budget.");
    assert_common_headers(&answer, DEFAULT_CONTENT_SECURITY_POLICY, "503");
}

#[tokio::test]
async fn the_explorer_exists_only_in_dev() {
    let dev = send("dev", request(Method::GET, "/api/graphql", None)).await;
    assert_eq!(dev.status, StatusCode::OK);
    assert!(
        dev.headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    assert_eq!(
        dev.headers[header::CONTENT_SECURITY_POLICY],
        EXPLORER_CONTENT_SECURITY_POLICY
    );
    for app_env in ["test", "prod"] {
        let answer = send(app_env, request(Method::GET, "/api/graphql", None)).await;
        assert_eq!(answer.status, StatusCode::METHOD_NOT_ALLOWED, "{app_env}");
        assert_eq!(answer.headers[header::ALLOW], "POST", "{app_env}");
        assert_eq!(
            answer.headers[header::CONTENT_TYPE],
            "application/problem+json",
            "{app_env}"
        );
    }
}

#[tokio::test]
async fn the_other_routes_behave_the_same_in_every_mode() {
    let probes = [
        (Method::GET, "/ping", None),
        (Method::GET, "/api/health", None),
        (Method::GET, "/api/example_api_resources", None),
        (Method::GET, "/api/unknown", None),
        (
            Method::POST,
            "/api/graphql",
            Some(r#"{"query":"{ exampleApiResources { id } }"}"#),
        ),
    ];
    for (method, path, body) in probes {
        let reference = send("dev", request(method.clone(), path, body)).await;
        for app_env in ["test", "prod"] {
            let answer = send(app_env, request(method.clone(), path, body)).await;
            assert_eq!(answer.status, reference.status, "{app_env} {path}");
            assert_eq!(answer.body, reference.body, "{app_env} {path}");
        }
    }
}

#[tokio::test]
async fn a_valid_inbound_request_id_is_kept_and_an_invalid_one_is_replaced() {
    let kept = Request::get("/ping")
        .header("x-request-id", "abc-123")
        .body(Body::empty())
        .unwrap();
    let kept = send("test", kept).await;
    assert_eq!(kept.headers["x-request-id"], "abc-123");

    let invalid = Request::get("/ping")
        .header("x-request-id", "a b")
        .body(Body::empty())
        .unwrap();
    let replaced = send("test", invalid).await;
    assert_ne!(replaced.headers["x-request-id"], "a b");
    assert_eq!(replaced.headers["x-request-id"].len(), 36);
}

#[tokio::test]
async fn no_response_is_compressed_and_no_other_protocol_is_advertised() {
    let app = router(adapters(), &config("test")).unwrap();
    for path in [
        "/ping",
        "/api/example_api_resources",
        "/api/docs/swagger-ui-bundle.js",
        "/api/unknown",
    ] {
        let mut bodies = Vec::new();
        for accept_encoding in [None, Some("gzip, deflate, br, zstd")] {
            let mut builder = Request::get(path);
            if let Some(value) = accept_encoding {
                builder = builder.header(header::ACCEPT_ENCODING, value);
            }
            let response = app
                .clone()
                .oneshot(builder.body(Body::empty()).unwrap())
                .await
                .unwrap();
            for name in [
                header::CONTENT_ENCODING,
                header::ALT_SVC,
                header::STRICT_TRANSPORT_SECURITY,
            ] {
                assert!(
                    !response.headers().contains_key(&name),
                    "{path} {accept_encoding:?}: {name}"
                );
            }
            bodies.push(response.into_body().collect().await.unwrap().to_bytes());
        }
        assert!(!bodies[0].is_empty(), "{path}");
        assert_eq!(bodies[0], bodies[1], "{path}");
    }
}

/// The types a handler parameter of this crate may have: their rejections are problems, or they
/// never reject (the optional principal that the authentication middleware puts into the request
/// extensions).
const ALLOWED_EXTRACTORS: [&str; 6] = [
    "State<ApiSchema>",
    "Option<Extension<Principal>>",
    "ApiPath<",
    "ApiJson<",
    "ValidatedQuery<",
    "ValidatedJson<",
];

/// The handler sources of the crate: every file under `src/http` and `src/graphql` with a
/// `pub async fn`, except the request id and the authentication middleware, whose parameters are
/// not extractors.
const HANDLER_SOURCES: [(&str, &str); 3] = [
    ("http/docs.rs", include_str!("../docs.rs")),
    ("http/ping.rs", include_str!("../ping.rs")),
    (
        "graphql/handler.rs",
        include_str!("../../graphql/handler.rs"),
    ),
];

/// Returns `name: parameter` for every parameter of a `pub async fn` of `source` whose type is not
/// an allowed extractor.
fn disallowed_parameters(source: &str) -> Vec<String> {
    let mut disallowed = Vec::new();
    for chunk in source.split("pub async fn ").skip(1) {
        let (name, after) = chunk.split_once('(').unwrap();
        let mut depth = 1_usize;
        let mut parameters = vec![String::new()];
        for character in after.chars() {
            match character {
                '(' | '<' => depth = depth.saturating_add(1),
                ')' | '>' => depth = depth.saturating_sub(1),
                _ => {}
            }
            if depth == 0 {
                break;
            }
            if character == ',' && depth == 1 {
                parameters.push(String::new());
            } else if let Some(current) = parameters.last_mut() {
                current.push(character);
            }
        }
        for parameter in parameters.iter().map(|parameter| parameter.trim()) {
            if parameter.is_empty() {
                continue;
            }
            let kind = parameter
                .split_once(": ")
                .map_or(parameter, |(_, kind)| kind)
                .trim();
            if !ALLOWED_EXTRACTORS
                .iter()
                .any(|allowed| kind.starts_with(allowed))
            {
                disallowed.push(format!("{}: {parameter}", name.trim()));
            }
        }
    }
    disallowed
}

/// The production files under `directory` of `src` that hold a `pub async fn`, as paths relative
/// to `src`.
fn files_with_handlers(directory: &str) -> Vec<String> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut pending = vec![root.join(directory)];
    let mut found = Vec::new();
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            pending.extend(
                std::fs::read_dir(&path)
                    .unwrap()
                    .map(|entry| entry.unwrap().path()),
            );
        } else if !path.ends_with("tests.rs")
            && std::fs::read_to_string(&path)
                .unwrap()
                .contains("pub async fn ")
        {
            let relative = path.strip_prefix(&root).unwrap();
            found.push(relative.to_string_lossy().replace('\\', "/"));
        }
    }
    found.sort_unstable();
    found
}

#[test]
fn handlers_use_only_the_problem_aware_extractors() {
    for (file, source) in HANDLER_SOURCES {
        assert_eq!(
            disallowed_parameters(source),
            Vec::<String>::new(),
            "{file}"
        );
    }
    assert!(
        HANDLER_SOURCES[0]
            .1
            .contains("ApiPath(file): ApiPath<String>")
    );
    assert!(HANDLER_SOURCES[2].1.contains("ApiJson(body): ApiJson<"));
    let mut expected: Vec<String> = HANDLER_SOURCES
        .iter()
        .map(|(file, _)| (*file).to_owned())
        .chain([
            "http/authentication.rs".to_owned(),
            "http/authorization.rs".to_owned(),
            "http/request_id.rs".to_owned(),
        ])
        .collect();
    expected.sort_unstable();
    let mut found = files_with_handlers("http");
    found.extend(files_with_handlers("graphql"));
    found.sort_unstable();
    assert_eq!(found, expected);
}

#[rstest::rstest]
#[case::raw_path("pub async fn h(Path(file): Path<String>) -> Response {}")]
#[case::raw_json("pub async fn h(State(s): State<ApiSchema>, Json(b): Json<Value>) -> Response {}")]
#[case::raw_query("pub async fn h(Query(q): Query<Params>) -> Response {}")]
#[case::raw_body("pub async fn h(body: String) -> Response {}")]
fn the_extractor_check_reports_a_planted_violation(#[case] source: &str) {
    assert_eq!(disallowed_parameters(source).len(), 1, "{source}");
}

#[test]
fn the_extractor_check_accepts_the_allowed_extractors() {
    let source = "pub async fn h(State(s): State<ApiSchema>, ApiPath(f): ApiPath<String>, \
        ApiJson(b): ApiJson<Map<String, Value>>, ValidatedQuery(q): ValidatedQuery<Q>, \
        ValidatedJson(j): ValidatedJson<J>) -> Response {}";

    assert_eq!(disallowed_parameters(source), Vec::<String>::new());
}

mod iam_authentication {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use axum::Router;
    use axum::body::Body;
    use axum::extract::Extension;
    use axum::http::{Method, Request, StatusCode, header};
    use axum::routing::get;
    use iam_application::Principal;
    use iam_domain::{
        AccessToken, AccessTokenParts, ServiceName, SessionId, SubjectId, TokenId, TokenIdentity,
        TokenRejection,
    };
    use rstest::rstest;
    use serde_json::Value;
    use shared_domain::Uuid;
    use test_support::log::LogRecorder;
    use test_support::token::FakeTokenRepository;

    use super::{Answer, adapters, config, request, send_to};
    use crate::bootstrap::router_with_iam_routes;
    use crate::http::AppState;
    use crate::http::authentication::AUTH_COOKIE;
    use crate::http::security_headers::DEFAULT_CONTENT_SECURITY_POLICY;

    /// The test-local protected route on the IAM router layer: the IAM context exposes no
    /// operation before Story 2.8.
    const PROTECTED: &str = "/api/test-protected";
    const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
    const USER_TOKEN: &str = "user.token.signature";
    const SERVICE_TOKEN: &str = "service.token.signature";
    const FOREIGN_SERVICE_TOKEN: &str = "foreign-service.token.signature";
    const LONG_SERVICE_TOKEN: &str = "long-service.token.signature";
    const EXPIRED_TOKEN: &str = "expired.token.signature";
    const REVOKED_TOKEN: &str = "revoked.token.signature";
    const MALFORMED_TOKEN: &str = "not-a-jws";

    fn identity(subject: SubjectId, audiences: &[&str], lifetime: u64) -> TokenIdentity {
        let session = match subject {
            SubjectId::User(_) => Some(SessionId::new("session-1").unwrap()),
            SubjectId::Service(_) => None,
        };
        TokenIdentity::from(
            &AccessToken::new(AccessTokenParts {
                subject,
                session,
                token_id: TokenId::new("jti-1").unwrap(),
                roles: Vec::new(),
                issued_at: SystemTime::UNIX_EPOCH,
                expires_at: SystemTime::UNIX_EPOCH
                    .checked_add(Duration::from_secs(lifetime))
                    .unwrap(),
            })
            .with_audiences(
                audiences
                    .iter()
                    .map(|&audience| audience.to_owned())
                    .collect(),
            ),
        )
    }

    fn service() -> SubjectId {
        SubjectId::Service(ServiceName::new("billing").unwrap())
    }

    fn tokens() -> FakeTokenRepository {
        let user = SubjectId::User(Uuid::parse(USER).unwrap());
        FakeTokenRepository::new()
            .accepting(USER_TOKEN, identity(user, &["vilnacrm-api"], 900))
            .accepting(
                SERVICE_TOKEN,
                identity(service(), &["vilnacrm-api", "vilnacrm-iam"], 900),
            )
            .accepting(
                FOREIGN_SERVICE_TOKEN,
                identity(service(), &["vilnacrm-api"], 300),
            )
            .accepting(
                LONG_SERVICE_TOKEN,
                identity(service(), &["vilnacrm-iam"], 901),
            )
            .rejecting(EXPIRED_TOKEN, TokenRejection::Expired)
            .rejecting(REVOKED_TOKEN, TokenRejection::Revoked)
    }

    async fn caller(Extension(principal): Extension<Principal>) -> String {
        principal.subject().to_string()
    }

    fn app() -> Router {
        let mut adapters = adapters();
        adapters.tokens = Arc::new(tokens());
        let routes: Router<AppState> = Router::new().route(PROTECTED, get(caller));
        router_with_iam_routes(adapters, &config("test"), routes).unwrap()
    }

    async fn get_with(headers: &[(header::HeaderName, String)]) -> Answer {
        let mut builder = Request::builder().method(Method::GET).uri(PROTECTED);
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        send_to(&app(), builder.body(Body::empty()).unwrap()).await
    }

    async fn bearer(token: &str) -> Answer {
        get_with(&[(header::AUTHORIZATION, format!("Bearer {token}"))]).await
    }

    fn assert_unauthenticated(answer: &Answer) {
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{}", answer.body);
        assert_eq!(answer.headers[header::WWW_AUTHENTICATE], "Bearer");
        assert_eq!(
            answer.headers[header::CONTENT_TYPE],
            "application/problem+json"
        );
        let problem: Value = serde_json::from_str(&answer.body).unwrap();
        assert_eq!(problem["status"], 401);
        assert_eq!(problem["detail"], "A valid bearer token is required.");
    }

    #[tokio::test]
    async fn a_request_without_authorization_is_the_401_problem_inside_the_outer_layers() {
        let answer = get_with(&[]).await;

        assert_unauthenticated(&answer);
        assert!(answer.headers.contains_key("x-request-id"));
        assert_eq!(answer.headers["x-content-type-options"], "nosniff");
        assert_eq!(
            answer.headers["content-security-policy"],
            DEFAULT_CONTENT_SECURITY_POLICY
        );
    }

    #[rstest]
    #[case::user(USER_TOKEN, USER)]
    #[case::service_with_the_iam_audience(SERVICE_TOKEN, "billing")]
    #[tokio::test]
    async fn a_valid_token_reaches_the_route_with_its_principal(
        #[case] token: &str,
        #[case] who: &str,
    ) {
        let answer = bearer(token).await;

        assert_eq!(answer.status, StatusCode::OK);
        assert_eq!(answer.body, who);
    }

    #[rstest]
    #[case::service_without_the_caller_audience(FOREIGN_SERVICE_TOKEN)]
    #[case::service_living_longer_than_allowed(LONG_SERVICE_TOKEN)]
    #[case::malformed(MALFORMED_TOKEN)]
    #[case::expired(EXPIRED_TOKEN)]
    #[case::revoked(REVOKED_TOKEN)]
    #[tokio::test]
    async fn every_refused_token_is_the_same_401_problem(#[case] token: &str) {
        let refused = bearer(token).await;
        let missing = get_with(&[]).await;

        assert_unauthenticated(&refused);
        assert_eq!(refused.body, missing.body);
    }

    #[tokio::test]
    async fn a_valid_token_in_the_cookie_is_authenticated_like_a_bearer_token() {
        let answer = get_with(&[(header::COOKIE, format!("{AUTH_COOKIE}={USER_TOKEN}"))]).await;

        assert_eq!(answer.status, StatusCode::OK);
        assert_eq!(answer.body, USER);
    }

    #[tokio::test]
    async fn an_invalid_cookie_token_is_the_same_401_problem() {
        let answer = get_with(&[(header::COOKIE, format!("{AUTH_COOKIE}={REVOKED_TOKEN}"))]).await;

        assert_unauthenticated(&answer);
    }

    #[rstest]
    #[case::ping("/ping", StatusCode::OK)]
    #[case::health("/api/health", StatusCode::NO_CONTENT)]
    #[case::docs("/api/docs", StatusCode::OK)]
    #[case::openapi("/api/docs/openapi.json", StatusCode::OK)]
    #[case::example_list("/api/example_api_resources", StatusCode::OK)]
    #[tokio::test]
    async fn the_template_routes_need_no_token(#[case] path: &str, #[case] status: StatusCode) {
        let answer = send_to(&app(), request(Method::GET, path, None)).await;

        assert_eq!(answer.status, status, "{path}");
        assert!(!answer.headers.contains_key(header::WWW_AUTHENTICATE));
    }

    #[rstest]
    #[case::without_a_token(None)]
    #[case::with_a_valid_token(Some(USER_TOKEN))]
    #[case::with_a_refused_token(Some(REVOKED_TOKEN))]
    #[tokio::test]
    async fn the_graphql_route_refuses_no_request(#[case] token: Option<&str>) {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri("/api/graphql")
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let body = Body::from(r#"{"query":"{ __typename }"}"#);

        let answer = send_to(&app(), builder.body(body).unwrap()).await;

        assert_eq!(answer.status, StatusCode::OK);
        let body: Value = serde_json::from_str(&answer.body).unwrap();
        assert_eq!(
            body,
            serde_json::json!({ "data": { "__typename": "Query" } })
        );
    }

    #[tokio::test]
    async fn the_authorization_value_never_reaches_a_span_or_a_log_line() {
        let (recorder, _guard) = LogRecorder::install();

        for token in [USER_TOKEN, REVOKED_TOKEN, MALFORMED_TOKEN] {
            let _answer = bearer(token).await;
        }

        let lines = recorder.lines();
        assert_ne!(lines, Vec::new());
        for line in lines {
            let printed = format!("{line:?}");
            for token in [USER_TOKEN, REVOKED_TOKEN, MALFORMED_TOKEN] {
                assert!(!printed.contains(token), "{printed}");
            }
        }
    }
}
