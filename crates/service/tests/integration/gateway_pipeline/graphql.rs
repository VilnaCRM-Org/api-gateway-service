//! The GraphQL routes of the pipeline (Story 10.8) in process: the coordinates a document selects
//! are authorized all or nothing, the original bytes reach the upstream, and a body that is no
//! accepted GraphQL request never does.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::header::{ALLOW, AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse as _, Response};
use http_body_util::BodyExt as _;
use iam_application::{
    FreshnessState, GraphQlRequestAnalyzer, ParseBudgetSettings, ParseObserver, ParseSite,
    RequestAuthorizer,
};
use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{
    AccessTokenVerifier, AssignmentScope, AssignmentState, BootClock as _, BootInstant,
    CatalogueEntryState, CompiledRoleSet, DocumentCache, ForwardError, FreshnessRule, GrantStatus,
    HttpMethod, PermissionGrant, PolicyVersion, PolicyView, RevocationView, RoleId, RouteFlag,
    RouteFlags, RouteState, ServiceName, SubjectRef, TokenMemo, TokenRepository, UpstreamForwarder,
    UpstreamState, UpstreamTarget,
};
use iam_infrastructure::{
    CachingTokenRepository, DocumentCacheSettings, MokaDocumentCache, MokaTokenMemo,
    SnapshotRevocationView, TokenMemoSettings,
};
use rstest::rstest;
use service::bootstrap::gateway::pipeline::{Pipeline, UnauditedCommands, router};
use shared_domain::{Clock, CommandBus, Uuid};
use test_support::boot_clock::FakeBootClock;
use test_support::clock::FixedClock;
use test_support::gateway_snapshot::{CountingPolicyView, GatewaySnapshot};
use test_support::id::SequenceUuidGenerator;
use test_support::route::{route, route_draft};
use test_support::seed::TestRng;
use test_support::upstream::upstream;
use tower::ServiceExt as _;

use super::{GOOD, HARD_BOUND, HOST, NOW, ROLE, USER, at, verifier};

const DEFAULT_LIMIT: i64 = 65_536;
const IAM_LIMIT: i64 = 6_291_456;
const DOCUMENT: &str = "{ orders { id total } }";

/// The bodies the upstream received.
#[derive(Debug, Default)]
struct Upstream {
    bodies: Mutex<Vec<Bytes>>,
}

impl Upstream {
    fn bodies(&self) -> Vec<Bytes> {
        self.bodies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[async_trait::async_trait]
impl UpstreamForwarder for Upstream {
    type Request = Request<Body>;
    type Response = Response;

    async fn forward(
        &self,
        _target: UpstreamTarget,
        request: Request<Body>,
    ) -> Result<Response, ForwardError> {
        let body = request.into_body().collect().await.unwrap().to_bytes();
        self.bodies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(body);
        Ok(StatusCode::OK.into_response())
    }
}

/// Where the documents were parsed.
#[derive(Debug, Default)]
struct Sites {
    seen: Mutex<Vec<ParseSite>>,
}

impl ParseObserver for Sites {
    fn parsed(&self, site: ParseSite, _bytes: usize) {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(site);
    }
}

struct Gateway {
    router: Router,
    upstream: Arc<Upstream>,
    sites: Arc<Sites>,
}

/// The typed entries of the service `orders`.
fn orders() -> Vec<CatalogueEntryState> {
    let field = |key: &str, return_type: &str| CatalogueEntryState {
        key: key.to_owned(),
        sensitive: false,
        audit_always: false,
        return_type: Some(return_type.to_owned()),
        possible_types: Vec::new(),
    };
    vec![
        field("gql:orders:Query.orders", "Order"),
        field("gql:orders:Order.id", "ID"),
        field("gql:orders:Order.total", "Int"),
    ]
}

/// A snapshot with the GraphQL routes `POST /api/graphql` (64 KiB) and `POST /iam/graphql` (6 MiB)
/// of the service `orders`, where `USER` holds `grants`.
fn snapshot(grants: &[&str]) -> GatewaySnapshot {
    let mut rng = TestRng::from_env();
    let users = UpstreamState::of(upstream(&mut rng, "users", "users").parts());
    let role = RoleId::parse(ROLE).unwrap();
    let granted = CompiledRoleSet::compile(
        grants
            .iter()
            .map(|raw| (PermissionGrant::parse(raw).unwrap(), GrantStatus::Active)),
    );
    let flags = RouteFlags::default().with(RouteFlag::Graphql, true);
    let mut default_route = route_draft(
        HOST,
        "/api/graphql",
        &[HttpMethod::Post],
        "orders",
        users.id,
    );
    default_route.flags = flags;
    default_route.body_limit = DEFAULT_LIMIT;
    let mut large_route = route_draft(
        HOST,
        "/iam/graphql",
        &[HttpMethod::Post],
        "orders",
        users.id,
    );
    large_route.flags = flags;
    large_route.body_limit = IAM_LIMIT;
    GatewaySnapshot::at(PolicyVersion::new(7).unwrap())
        .with_upstream(users)
        .with_route(RouteState::of(route(&mut rng, &default_route).parts()))
        .with_route(RouteState::of(route(&mut rng, &large_route).parts()))
        .with_catalogue(ServiceName::new("orders").unwrap(), orders())
        .with_assignments(
            SubjectRef::user(Uuid::parse(USER).unwrap()),
            vec![AssignmentState {
                role,
                scope: AssignmentScope::Global,
                expires_at_micros: None,
            }],
        )
        .with_role_set(role, granted)
}

fn gateway(grants: &[&str]) -> Gateway {
    gateway_with(grants, ParseBudgetSettings::default())
}

fn gateway_with(grants: &[&str], budget: ParseBudgetSettings) -> Gateway {
    let view = Arc::new(CountingPolicyView::serving(snapshot(grants)));
    let upstream = Arc::new(Upstream::default());
    let sites = Arc::new(Sites::default());
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
        PolicyVersion::new(7).unwrap(),
    );
    let clock: Arc<dyn Clock> = Arc::new(FixedClock::at(at(NOW)));
    let policy: Arc<dyn PolicyView> = Arc::<CountingPolicyView>::clone(&view);
    let verifier: Arc<dyn AccessTokenVerifier> = Arc::new(verifier());
    let memo: Arc<dyn TokenMemo> = Arc::new(MokaTokenMemo::new(
        TokenMemoSettings {
            capacity: 1_000,
            max_ttl: Duration::from_mins(5),
        },
        Arc::clone(&clock),
    ));
    let revocations: Arc<dyn RevocationView> =
        Arc::new(SnapshotRevocationView::new(Arc::clone(&policy)));
    let tokens = Arc::new(CachingTokenRepository::new(verifier, memo, revocations));
    let token_port: Arc<dyn TokenRepository> = Arc::<CachingTokenRepository>::clone(&tokens);
    let commands: Arc<dyn CommandBus> = Arc::new(UnauditedCommands);
    let cache: Arc<dyn DocumentCache> = Arc::new(MokaDocumentCache::new(DocumentCacheSettings {
        capacity_bytes: 1 << 20,
        time_to_idle: Duration::from_mins(1),
    }));
    let observer = Arc::<Sites>::clone(&sites);
    let analyzer = GraphQlRequestAnalyzer::new(cache, budget).with_observer(observer);
    let authorizer = RequestAuthorizer::new(
        token_port,
        clock,
        Arc::new(SequenceUuidGenerator::starting_at(1)),
        commands,
    )
    .with_graphql(Arc::new(analyzer));
    let forwarder = Arc::<Upstream>::clone(&upstream);
    let pipeline = Pipeline::new(policy, freshness, tokens, Arc::new(authorizer), forwarder);
    Gateway {
        router: router(pipeline),
        upstream,
        sites,
    }
}

fn envelope(document: &str) -> String {
    serde_json::json!({ "query": document }).to_string()
}

fn post(path: &str, content_type: &str, body: impl Into<Body>) -> Request<Body> {
    Request::post(path)
        .header("host", HOST)
        .header(AUTHORIZATION, format!("Bearer {GOOD}"))
        .header(CONTENT_TYPE, content_type)
        .body(body.into())
        .unwrap()
}

fn json(body: &str) -> Request<Body> {
    post("/api/graphql", "application/json", body.to_owned())
}

async fn send(gateway: &Gateway, request: Request<Body>) -> Response {
    gateway.router.clone().oneshot(request).await.unwrap()
}

async fn text(response: Response) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn a_subject_holding_every_coordinate_reaches_the_upstream_with_the_original_bytes() {
    let gateway = gateway(&[
        "gql:orders:Query.orders",
        "gql:orders:Order.id",
        "gql:orders:Order.total",
    ]);
    let body = envelope(DOCUMENT);

    let response = send(&gateway, json(&body)).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(gateway.upstream.bodies(), vec![Bytes::from(body)]);
}

#[tokio::test]
async fn a_subject_holding_some_of_the_coordinates_gets_403_that_lists_none() {
    let gateway = gateway(&["gql:orders:Query.orders", "gql:orders:Order.id"]);

    let response = send(&gateway, json(&envelope(DOCUMENT))).await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = text(response).await;
    assert!(
        !body.contains("Order.total") && !body.contains("orders"),
        "{body}"
    );
    assert_eq!(gateway.upstream.bodies(), Vec::<Bytes>::new());
}

#[tokio::test]
async fn a_batch_with_one_denied_operation_gets_403_and_one_of_eleven_gets_400() {
    let gateway = gateway(&["gql:orders:Query.orders", "gql:orders:Order.id"]);
    let allowed = serde_json::json!({ "query": "{ orders { id } }" });
    let denied = serde_json::json!({ "query": DOCUMENT });
    let mut ten = vec![allowed.clone(); 9];
    ten.push(denied);
    let eleven = vec![allowed; 11];

    let first = send(&gateway, json(&serde_json::Value::from(ten).to_string())).await;
    let second = send(&gateway, json(&serde_json::Value::from(eleven).to_string())).await;

    assert_eq!(first.status(), StatusCode::FORBIDDEN);
    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
    assert_eq!(gateway.upstream.bodies(), Vec::<Bytes>::new());
}

#[rstest]
#[case::persisted_query(r#"{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"ab"}}}"#)]
#[case::document_id(r#"{"documentId":"abc"}"#)]
#[case::empty_query(r#"{"query":""}"#)]
#[case::unknown_member(r#"{"query":"{ orders { id } }","debug":true}"#)]
#[case::duplicate_query(r#"{"query":"{ orders { id } }","query":"{ orders { total } }"}"#)]
#[tokio::test]
async fn a_body_that_is_no_accepted_envelope_gets_400_and_the_upstream_receives_nothing(
    #[case] body: &str,
) {
    let gateway = gateway(&["gql:orders:*"]);

    let response = send(&gateway, json(body)).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(gateway.upstream.bodies(), Vec::<Bytes>::new());
}

#[rstest]
#[case("multipart/form-data; boundary=x")]
#[case("text/plain")]
#[tokio::test]
async fn a_body_that_is_not_json_gets_415(#[case] content_type: &str) {
    let gateway = gateway(&["gql:orders:*"]);

    let response = send(
        &gateway,
        post("/api/graphql", content_type, envelope(DOCUMENT)),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(gateway.upstream.bodies(), Vec::<Bytes>::new());
}

#[tokio::test]
async fn a_get_with_the_operation_in_the_query_string_gets_405_with_allow_post() {
    let gateway = gateway(&["gql:orders:*"]);
    let request = Request::get("/api/graphql?query=%7B%20orders%20%7B%20id%20%7D%20%7D")
        .header("host", HOST)
        .header(AUTHORIZATION, format!("Bearer {GOOD}"))
        .body(Body::empty())
        .unwrap();

    let response = send(&gateway, request).await;

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers().get(ALLOW).unwrap(), "POST");
    assert_eq!(gateway.upstream.bodies(), Vec::<Bytes>::new());
}

#[tokio::test]
async fn a_body_of_65_kib_is_refused_on_a_default_route_and_5_mib_is_accepted_on_the_large_one() {
    let gateway = gateway(&["gql:orders:*"]);
    let padded = |size: usize| {
        serde_json::json!({ "query": "{ orders { id } }", "variables": { "pad": "x".repeat(size) } })
            .to_string()
    };

    let small_route = send(&gateway, json(&padded(65 * 1024))).await;
    let large_route = send(
        &gateway,
        post("/iam/graphql", "application/json", padded(5 * 1024 * 1024)),
    )
    .await;

    assert_eq!(small_route.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(large_route.status(), StatusCode::OK);
    assert_eq!(gateway.upstream.bodies().len(), 1);
}

#[tokio::test]
async fn an_introspection_query_is_forwarded_only_for_the_holder_of_the_introspection_key() {
    let query = envelope("{ __schema { queryType { name } } }");
    let holder = gateway(&["gql:orders:__introspection"]);
    let other = gateway(&["gql:orders:Query.orders"]);

    let allowed = send(&holder, json(&query)).await;
    let denied = send(&other, json(&query)).await;

    assert_eq!(allowed.status(), StatusCode::OK);
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(holder.upstream.bodies().len(), 1);
    assert_eq!(other.upstream.bodies(), Vec::<Bytes>::new());
}

#[tokio::test]
async fn a_large_document_is_parsed_on_the_blocking_pool_and_a_small_one_on_the_worker() {
    let gateway = gateway(&["gql:orders:*"]);
    let large = format!("{{ orders {{ id }} }}{}", " ".repeat(40_000));

    let first = send(&gateway, json(&envelope(&large))).await;
    let second = send(&gateway, json(&envelope(DOCUMENT))).await;

    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);
    let seen = gateway
        .sites
        .seen
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    assert_eq!(*seen, [ParseSite::BlockingPool, ParseSite::Worker]);
}

#[tokio::test]
async fn a_subject_over_its_parse_budget_gets_429_while_cached_documents_are_still_served() {
    let gateway = gateway_with(
        &["gql:orders:*"],
        ParseBudgetSettings {
            misses_per_second: 1,
            bytes_per_second: 1_048_576,
        },
    );

    let first = send(&gateway, json(&envelope("{ orders { id } }"))).await;
    let over = send(&gateway, json(&envelope("{ orders { total } }"))).await;
    let cached = send(&gateway, json(&envelope("{ orders { id } }"))).await;

    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(over.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(cached.status(), StatusCode::OK);
}
