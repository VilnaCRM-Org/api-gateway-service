use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{Method, StatusCode};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::Response;
use axum::routing::{get, post};
use http_body_util::BodyExt as _;
use iam_application::http::access_validation::ACCESS_VALIDATION_BATCH_BODY_LIMIT_BYTES;
use iam_application::{
    AccessDecisionService, IamAccessGuard, IamError, Principal, RecordRejectedAttemptCommand,
    ServiceCatalogLoader,
};
use iam_domain::{
    AccessToken, AccessTokenParts, AssignmentScope, CompiledRoleSet, GrantStatus, HttpMethod,
    PathTemplate, PermissionFlags, PermissionGrant, PolicyReadRepository, RestOperation,
    RestOperationSet, RoleAssignment, RoleId, ServiceCatalog, ServiceName, SessionId, SubjectId,
    SubjectPolicy, SubjectRef, TokenId, TokenIdentity,
};
use serde_json::Value;
use shared_domain::Uuid;
use test_support::bus::FakeCommandBus;
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::policy_epoch::seeded_policy_epoch;
use test_support::policy_read::FakePolicyReadRepository;
use test_support::token::FakeTokenRepository;
use tower::ServiceExt as _;

use super::require_operation;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const NOW: u64 = 1_800_000_000;

type Recorded = Arc<Mutex<Vec<RecordRejectedAttemptCommand>>>;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn user() -> SubjectRef {
    SubjectRef::user(Uuid::parse(USER).unwrap())
}

fn principal() -> Principal {
    Principal::from(TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(Uuid::parse(USER).unwrap()),
        session: Some(SessionId::new("session-1").unwrap()),
        token_id: TokenId::new("jti-1").unwrap(),
        roles: Vec::new(),
        issued_at: at(NOW - 60),
        expires_at: at(NOW + 840),
    })))
}

fn catalog() -> ServiceCatalog {
    let mut operations = RestOperationSet::new();
    for (method, template) in [
        (HttpMethod::Post, "/api/roles"),
        (HttpMethod::Get, "/api/roles/{id}"),
    ] {
        operations
            .insert(RestOperation {
                method,
                template: PathTemplate::from_openapi_path(template).unwrap(),
                label: None,
                flags: PermissionFlags::NONE,
            })
            .unwrap();
    }
    ServiceCatalog::new(
        ServiceName::iam().clone(),
        seeded_policy_epoch(),
        vec![operations],
        Vec::new(),
    )
}

fn repository(grants: &[&str]) -> FakePolicyReadRepository {
    let role = RoleId::parse("00000000-0000-7000-8000-000000000101").unwrap();
    let grants = grants
        .iter()
        .map(|raw| (PermissionGrant::parse(raw).unwrap(), GrantStatus::Active));
    let policy = SubjectPolicy::new(
        seeded_policy_epoch(),
        vec![RoleAssignment::new(role, AssignmentScope::Global, None)],
        BTreeMap::from([(role, CompiledRoleSet::compile(grants))]),
    );
    FakePolicyReadRepository::new()
        .with_catalog(catalog())
        .with_subject(user(), policy)
}

fn guard_over(policy: impl PolicyReadRepository + 'static) -> (Arc<IamAccessGuard>, Recorded) {
    let policy: Arc<dyn PolicyReadRepository> = Arc::new(policy);
    let decisions = AccessDecisionService::new(
        Arc::new(FakeTokenRepository::new()),
        ServiceCatalogLoader::new(Arc::clone(&policy)),
        policy,
        Arc::new(FixedClock::at(at(NOW))),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );
    let recorded: Recorded = Arc::default();
    let sink = Arc::clone(&recorded);
    let bus = FakeCommandBus::handling::<RecordRejectedAttemptCommand, _>(move |command| {
        sink.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(command);
        Ok::<(), IamError>(())
    });
    (
        Arc::new(IamAccessGuard::new(Arc::new(decisions), Arc::new(bus))),
        recorded,
    )
}

async fn put_principal(
    State(principal): State<Principal>,
    mut request: Request,
    next: Next,
) -> Response {
    request.extensions_mut().insert(principal);
    next.run(request).await
}

/// The routes under the guard; with `authenticated` the caller is put in front of it.
fn app(guard: Arc<IamAccessGuard>, authenticated: bool) -> Router {
    let routes = Router::new()
        .route("/api/roles", post(async || StatusCode::CREATED))
        .route("/api/roles/{id}", get(async || StatusCode::OK))
        .route("/api/unlisted", get(async || StatusCode::OK))
        .route("/api/access-validations", post(async |body: String| body))
        .route(
            "/api/access-validations/batch",
            post(async |body: String| body),
        )
        .route_layer(from_fn_with_state(guard, require_operation));
    if authenticated {
        routes.route_layer(from_fn_with_state(principal(), put_principal))
    } else {
        routes
    }
}

struct Answer {
    status: StatusCode,
    content_type: Option<String>,
    body: String,
}

async fn call(app: Router, method: Method, path: &str, request_id: Option<&str>) -> Answer {
    send(app, method, path, request_id, Body::empty()).await
}

async fn post_body(app: Router, path: &str, body: String) -> Answer {
    send(app, Method::POST, path, None, Body::from(body)).await
}

async fn send(
    app: Router,
    method: Method,
    path: &str,
    request_id: Option<&str>,
    body: Body,
) -> Answer {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(id) = request_id {
        builder = builder.header("x-request-id", id);
    }
    let response = app.oneshot(builder.body(body).unwrap()).await.unwrap();
    let (parts, body) = response.into_parts();
    Answer {
        status: parts.status,
        content_type: parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        body: String::from_utf8(body.collect().await.unwrap().to_bytes().to_vec()).unwrap(),
    }
}

fn refusals(recorded: &Recorded) -> Vec<RecordRejectedAttemptCommand> {
    recorded
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

#[tokio::test]
async fn a_caller_with_the_catalogue_key_reaches_the_handler() {
    let (guard, recorded) = guard_over(repository(&["rest:iam:POST /api/roles"]));

    let answer = call(app(guard, true), Method::POST, "/api/roles", None).await;

    assert_eq!(answer.status, StatusCode::CREATED);
    assert!(refusals(&recorded).is_empty());
}

#[tokio::test]
async fn a_templated_route_is_matched_on_its_template_and_checked_on_the_concrete_path() {
    let (guard, _recorded) = guard_over(repository(&["rest:iam:GET /api/roles/{}"]));
    let path = "/api/roles/0190f2a8-7b3c-7d4e-8f10-1234567890ab";

    let answer = call(app(guard, true), Method::GET, path, None).await;

    assert_eq!(answer.status, StatusCode::OK);
}

#[tokio::test]
async fn a_caller_without_the_key_gets_a_403_problem_and_the_refusal_is_offered() {
    let (guard, recorded) = guard_over(repository(&[]));

    let answer = call(
        app(guard, true),
        Method::POST,
        "/api/roles",
        Some("request-7"),
    )
    .await;

    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(
        answer.content_type.as_deref(),
        Some("application/problem+json")
    );
    let problem: Value = serde_json::from_str(&answer.body).unwrap();
    assert_eq!(problem["status"], 403);
    let offered = refusals(&recorded);
    assert_eq!(offered.len(), 1);
    assert_eq!(offered[0].action.as_str(), "role.create");
    assert_eq!(offered[0].actor.to_string(), format!("user:{USER}"));
    assert_eq!(
        offered[0]
            .request_id
            .as_ref()
            .map(iam_domain::RequestId::as_str),
        Some("request-7")
    );
}

#[tokio::test]
async fn a_route_without_a_row_is_refused_even_for_a_caller_with_every_key() {
    let (guard, recorded) = guard_over(repository(&["rest:iam:*", "iam:validate:*"]));

    let answer = call(app(guard, true), Method::GET, "/api/unlisted", None).await;

    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(refusals(&recorded)[0].action.as_str(), "operation.unlisted");
}

#[tokio::test]
async fn a_request_without_a_principal_fails_closed_with_401_and_records_nothing() {
    let (guard, recorded) = guard_over(repository(&["rest:iam:POST /api/roles"]));

    let answer = call(app(guard, false), Method::POST, "/api/roles", None).await;

    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert!(refusals(&recorded).is_empty());
}

#[tokio::test]
async fn an_unreadable_policy_is_a_500_and_records_nothing() {
    let (guard, recorded) = guard_over(FakePolicyReadRepository::failing());

    let answer = call(app(guard, true), Method::POST, "/api/roles", None).await;

    assert_eq!(answer.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(refusals(&recorded).is_empty());
}

#[tokio::test]
async fn a_caller_validating_for_a_service_it_holds_the_key_of_reaches_the_handler_with_its_body() {
    let (guard, recorded) = guard_over(repository(&["iam:validate:core"]));
    let body = r#"{"service":"core","request_id":"r-1"}"#;

    let answer = post_body(app(guard, true), "/api/access-validations", body.to_owned()).await;

    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body, body);
    assert!(refusals(&recorded).is_empty());
}

#[tokio::test]
async fn a_caller_validating_for_another_service_gets_a_403_problem_and_the_refusal_is_offered() {
    let (guard, recorded) = guard_over(repository(&["iam:validate:core"]));
    let body = r#"{"service":"payment","request_id":"r-1"}"#;

    let answer = post_body(app(guard, true), "/api/access-validations", body.to_owned()).await;

    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(
        answer.content_type.as_deref(),
        Some("application/problem+json")
    );
    assert_eq!(refusals(&recorded)[0].action.as_str(), "access.validate");
}

#[tokio::test]
async fn one_item_for_a_service_the_caller_may_not_validate_refuses_the_whole_batch() {
    let (guard, recorded) = guard_over(repository(&["iam:validate:core"]));
    let body = r#"{"checks":[{"service":"core"},{"service":"payment"}]}"#;

    let answer = post_body(
        app(guard, true),
        "/api/access-validations/batch",
        body.to_owned(),
    )
    .await;

    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(
        refusals(&recorded)[0].action.as_str(),
        "access.validate_batch"
    );
}

#[tokio::test]
async fn a_batch_of_services_the_caller_holds_keys_of_reaches_the_handler() {
    let (guard, _recorded) = guard_over(repository(&["iam:validate:core", "iam:validate:payment"]));
    let body = r#"{"checks":[{"service":"core"},{"service":"payment"}]}"#;

    let answer = post_body(
        app(guard, true),
        "/api/access-validations/batch",
        body.to_owned(),
    )
    .await;

    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body, body);
}

#[tokio::test]
async fn a_body_above_the_batch_limit_is_a_413_problem() {
    let (guard, recorded) = guard_over(repository(&["iam:validate:*"]));
    let body = " ".repeat(ACCESS_VALIDATION_BATCH_BODY_LIMIT_BYTES + 1);

    let answer = post_body(app(guard, true), "/api/access-validations/batch", body).await;

    assert_eq!(answer.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(refusals(&recorded).is_empty());
}

#[tokio::test]
async fn a_body_that_names_no_service_needs_the_wildcard() {
    let (guard, recorded) = guard_over(repository(&["iam:validate:core"]));

    let answer = post_body(
        app(guard, true),
        "/api/access-validations",
        "not json".to_owned(),
    )
    .await;

    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(refusals(&recorded)[0].action.as_str(), "access.validate");
}
