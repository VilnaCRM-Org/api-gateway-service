//! The decision listener of the gateway through its production wiring: tokens signed at test time
//! with an ephemeral RSA key, verified by `JwtAccessTokenVerifier`, the caller rule and the
//! decisions read from a snapshot held in memory (Story 10.11).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt as _;
use iam_application::{FreshnessState, PolicyVersionBoard, ReadYourWritesBarrier};
use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{
    AssignmentScope, AssignmentState, BootClock as _, BootInstant, CallerTokenRule,
    CompiledRoleSet, FreshnessRule, GrantStatus, PermissionGrant, PolicyVersion, RoleId,
    ServiceName, SubjectRef, TokenLifetimeRule,
};
use iam_infrastructure::JwtSettings;
use serde_json::{Value, json};
use service::bootstrap::gateway::decision::{DecisionPorts, router, router_with_barrier};
use service::cli::GatewayArgs;
use service::config::GatewayConfig;
use test_support::access_token::DEVELOPMENT_PUBLIC_KEYS_FILE;
use test_support::boot_clock::FakeBootClock;
use test_support::clock::FixedClock;
use test_support::decision_snapshot::DecisionSnapshot;
use test_support::policy_view::FakePolicyView;
use tower::ServiceExt as _;

use crate::authentication::test_keys::{
    AUDIENCE, ISSUER, NOW, TestKey, key_file, scratch_dir, service_claims, user_claims,
};

const CALLER_AUDIENCE: &str = "vilnacrm-iam";
const HARD_BOUND: Duration = Duration::from_secs(15);

fn config(name: &str, key: &TestKey) -> GatewayConfig {
    let mut args = GatewayArgs::default();
    args.service.app_env = Some("test".to_owned());
    args.service.tokens.public_keys_file = Some(DEVELOPMENT_PUBLIC_KEYS_FILE.to_owned());
    args.service.kafka.bootstrap_servers = Some("localhost:9092".to_owned());
    args.service.kafka.security_protocol = Some("PLAINTEXT".to_owned());
    let mut config = GatewayConfig::from_args(&args).unwrap();
    let path = scratch_dir(name).join("keys.pem");
    std::fs::write(&path, key_file(&[key])).unwrap();
    config.tokens.public_keys_file = path;
    config.tokens.jwt = JwtSettings {
        issuer: ISSUER.to_owned(),
        audience: AUDIENCE.to_owned(),
        lifetime: TokenLifetimeRule::new(Duration::from_mins(15), Duration::from_secs(30)),
    };
    config.tokens.callers =
        CallerTokenRule::new(CALLER_AUDIENCE.to_owned(), Duration::from_mins(10));
    config
}

fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

/// The service caller of the test token: `user-service`.
fn caller() -> SubjectRef {
    SubjectRef::service(ServiceName::new("user-service").unwrap())
}

/// A snapshot at version 4 in which the caller holds `grants` globally.
fn snapshot_granting(grants: &[&str]) -> DecisionSnapshot {
    let role = RoleId::parse("00000000-0000-7000-8000-000000000101").unwrap();
    let compiled = CompiledRoleSet::compile(
        grants
            .iter()
            .map(|raw| (PermissionGrant::parse(raw).unwrap(), GrantStatus::Active)),
    );
    DecisionSnapshot::at(version(4))
        .with_assignments(
            caller(),
            vec![AssignmentState {
                role,
                scope: AssignmentScope::Global,
                expires_at_micros: None,
            }],
        )
        .with_role_set(role, compiled)
}

struct Gateway {
    app: Router,
    boot: Arc<FakeBootClock>,
}

/// The decision router over `snapshot`, fresh until the boot clock advances past the hard bound.
fn gateway(name: &str, key: &TestKey, snapshot: DecisionSnapshot) -> Gateway {
    gateway_barring(name, key, snapshot, None)
}

/// The same router behind the read-your-writes barrier over `board`, when there is one: the pod
/// has published version 4 and waits one second for a version it has seen.
fn gateway_barring(
    name: &str,
    key: &TestKey,
    snapshot: DecisionSnapshot,
    board: Option<Arc<PolicyVersionBoard>>,
) -> Gateway {
    let boot = Arc::new(FakeBootClock::starting_at(BootInstant::from_elapsed(
        Duration::from_secs(100),
    )));
    let freshness = Arc::new(FreshnessState::new(
        FreshnessRule::new(HARD_BOUND, Duration::from_secs(2)),
        Arc::<FakeBootClock>::clone(&boot),
    ));
    freshness.attach(
        FreshnessProof {
            taken_at: boot.now(),
            watermark: 1,
        },
        version(4),
    );
    let view = Arc::new(FakePolicyView::with_snapshot(Arc::new(snapshot)));
    let barrier = board.map(|board| {
        Arc::new(ReadYourWritesBarrier::new(
            Arc::<FakePolicyView>::clone(&view),
            board,
            Duration::from_secs(1),
        ))
    });
    let ports = DecisionPorts {
        view,
        freshness,
        clock: Arc::new(FixedClock::at(
            SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(NOW))
                .unwrap(),
        )),
    };
    let config = config(name, key);
    let app = match barrier {
        Some(barrier) => router_with_barrier(&config, ports, &barrier),
        None => router(&config, ports),
    };
    Gateway {
        app: app.unwrap(),
        boot,
    }
}

struct Answer {
    status: StatusCode,
    challenge: Option<String>,
    body: Value,
}

async fn post(gateway: &Gateway, path: &str, token: &str, body: &Value) -> Answer {
    let response = gateway
        .app
        .clone()
        .oneshot(
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .map(|value| value.to_str().unwrap().to_owned());
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    Answer {
        status,
        challenge,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    }
}

fn check(request_id: &str) -> Value {
    with_credential(request_id, "subject-token")
}

fn with_credential(request_id: &str, credential: &str) -> Value {
    json!({
        "credential": credential,
        "service": "orders",
        "permissions": ["rest:orders:GET /api/orders"],
        "requestId": request_id,
    })
}

#[tokio::test]
async fn a_service_caller_without_the_validate_key_gets_403() {
    let key = TestKey::generate();
    let gateway = gateway("decision-403", &key, DecisionSnapshot::at(version(4)));
    let token = key.sign(&service_claims());

    let answer = post(&gateway, "/api/access-validations", &token, &check("r1")).await;

    assert_eq!(answer.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_service_token_without_the_caller_audience_gets_401_with_the_bearer_challenge() {
    let key = TestKey::generate();
    let gateway = gateway("decision-401", &key, snapshot_granting(&["iam:validate:*"]));
    let mut claims = service_claims();
    claims["aud"] = json!(AUDIENCE);
    let token = key.sign(&claims);

    let answer = post(&gateway, "/api/access-validations", &token, &check("r1")).await;

    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert_eq!(answer.challenge.as_deref(), Some("Bearer"));
}

#[tokio::test]
async fn a_caller_with_the_key_of_the_target_service_is_decided_from_the_snapshot() {
    let key = TestKey::generate();
    let gateway = gateway(
        "decision-200",
        &key,
        snapshot_granting(&["iam:validate:orders"]),
    );
    let token = key.sign(&service_claims());
    let subject = key.sign(&user_claims());

    let answer = post(
        &gateway,
        "/api/access-validations",
        &token,
        &with_credential("r1", &subject),
    )
    .await;

    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body["decision"], "deny");
    assert_eq!(answer.body["reason"], "unknown_service");
    assert_eq!(answer.body["requestId"], "r1");
}

#[tokio::test]
async fn a_caller_with_the_key_of_another_service_gets_403() {
    let key = TestKey::generate();
    let gateway = gateway(
        "decision-other",
        &key,
        snapshot_granting(&["iam:validate:billing"]),
    );
    let token = key.sign(&service_claims());

    let answer = post(&gateway, "/api/access-validations", &token, &check("r1")).await;

    assert_eq!(answer.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_proof_older_than_the_hard_bound_is_200_with_deny_and_unavailable() {
    let key = TestKey::generate();
    let gateway = gateway(
        "decision-stale",
        &key,
        snapshot_granting(&["iam:validate:*"]),
    );
    let token = key.sign(&service_claims());
    gateway.boot.advance(HARD_BOUND + Duration::from_millis(1));

    let single = post(&gateway, "/api/access-validations", &token, &check("r1")).await;
    let batch = post(
        &gateway,
        "/api/access-validations/batch",
        &token,
        &json!({ "checks": [check("r1"), check("r2")] }),
    )
    .await;

    assert_eq!(single.status, StatusCode::OK);
    assert_eq!(single.body["decision"], "deny");
    assert_eq!(single.body["reason"], "unavailable");
    assert_eq!(batch.status, StatusCode::OK);
    assert_eq!(batch.body["results"][1]["reason"], "unavailable");
}

#[tokio::test]
async fn a_minimum_policy_version_the_pod_has_not_applied_is_deny_and_unavailable() {
    let key = TestKey::generate();
    let gateway = gateway(
        "decision-minimum",
        &key,
        snapshot_granting(&["iam:validate:*"]),
    );
    let token = key.sign(&service_claims());
    let mut ahead = check("r1");
    ahead["minPolicyVersion"] = json!(5);

    let answer = post(&gateway, "/api/access-validations", &token, &ahead).await;

    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body["decision"], "deny");
    assert_eq!(answer.body["reason"], "unavailable");
}

#[tokio::test]
async fn behind_the_barrier_a_version_above_the_highest_seen_is_deny_and_unavailable_at_once() {
    let key = TestKey::generate();
    let board = Arc::new(PolicyVersionBoard::new());
    board.note_published(Some(version(4)));
    let gateway = gateway_barring(
        "decision-barrier-unseen",
        &key,
        snapshot_granting(&["iam:validate:*"]),
        Some(board),
    );
    let token = key.sign(&service_claims());
    let mut ahead = check("r1");
    ahead["minPolicyVersion"] = json!(5);

    let answer = post(&gateway, "/api/access-validations", &token, &ahead).await;

    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body["decision"], "deny");
    assert_eq!(answer.body["reason"], "unavailable");
}

#[tokio::test(start_paused = true)]
async fn behind_the_barrier_a_seen_version_that_is_not_published_in_time_is_deny_and_unavailable() {
    let key = TestKey::generate();
    let board = Arc::new(PolicyVersionBoard::new());
    board.note_published(Some(version(4)));
    board.note_seen(version(5));
    let gateway = gateway_barring(
        "decision-barrier-seen",
        &key,
        snapshot_granting(&["iam:validate:*"]),
        Some(board),
    );
    let token = key.sign(&service_claims());
    let mut ahead = check("r1");
    ahead["minPolicyVersion"] = json!(5);

    let answer = post(&gateway, "/api/access-validations", &token, &ahead).await;

    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body["reason"], "unavailable");
}

#[tokio::test]
async fn a_batch_of_101_checks_is_422_over_rest_and_validation_failed_over_graphql() {
    let key = TestKey::generate();
    let gateway = gateway(
        "decision-batch",
        &key,
        snapshot_granting(&["iam:validate:*"]),
    );
    let token = key.sign(&service_claims());
    let checks: Vec<Value> = (0..101).map(|n| check(&format!("r{n}"))).collect();
    let inputs: Vec<Value> = (0..101)
        .map(|n| {
            json!({
                "credential": "subject-token",
                "service": "orders",
                "permissions": ["rest:orders:GET /api/orders"],
                "requestId": format!("r{n}"),
            })
        })
        .collect();

    let rest = post(
        &gateway,
        "/api/access-validations/batch",
        &token,
        &json!({ "checks": checks }),
    )
    .await;
    let graphql = post(
        &gateway,
        "/api/graphql",
        &token,
        &json!({
            "query": "query($inputs: [ValidateAccessInput!]!) { validateAccessBatch(inputs: $inputs) { decision } }",
            "variables": { "inputs": inputs },
        }),
    )
    .await;

    assert_eq!(rest.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(graphql.status, StatusCode::OK);
    assert_eq!(
        graphql.body["errors"][0]["extensions"]["code"],
        "VALIDATION_FAILED"
    );
}

#[tokio::test]
async fn a_management_field_over_graphql_is_an_unknown_field() {
    let key = TestKey::generate();
    let gateway = gateway(
        "decision-graphql",
        &key,
        snapshot_granting(&["iam:validate:*"]),
    );
    let token = key.sign(&service_claims());

    let answer = post(
        &gateway,
        "/api/graphql",
        &token,
        &json!({ "query": "{ createRole(input: { name: \"x\" }) { id } }" }),
    )
    .await;

    assert_eq!(answer.status, StatusCode::OK);
    let message = answer.body["errors"][0]["message"].as_str().unwrap();
    assert!(message.contains("Unknown field"), "{message}");
}

#[tokio::test]
async fn a_decision_over_graphql_is_the_decision_of_rest_and_a_token_resolves() {
    let key = TestKey::generate();
    let gateway = gateway(
        "decision-graphql-fields",
        &key,
        snapshot_granting(&["iam:validate:*"]),
    );
    let token = key.sign(&service_claims());
    let subject = key.sign(&user_claims());
    let input = with_credential("g1", &subject);

    let decision = post(
        &gateway,
        "/api/graphql",
        &token,
        &json!({
            "query": "query($input: ValidateAccessInput!) { validateAccess(input: $input) { decision reason requestId } }",
            "variables": { "input": input },
        }),
    )
    .await;
    let resolution = post(
        &gateway,
        "/api/graphql",
        &token,
        &json!({
            "query": "query($input: ResolveTokenInput!) { resolveToken(input: $input) { resolved } }",
            "variables": { "input": { "credential": subject } },
        }),
    )
    .await;

    assert_eq!(decision.status, StatusCode::OK);
    assert_eq!(decision.body["data"]["validateAccess"]["decision"], "deny");
    assert_eq!(
        decision.body["data"]["validateAccess"]["reason"],
        "unknown_service"
    );
    assert_eq!(resolution.status, StatusCode::OK);
    assert_eq!(
        resolution.body["data"]["resolveToken"]["resolved"], true,
        "{}",
        resolution.body
    );
}
