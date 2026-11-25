//! The east-west listener (Story 10.13, FR-90) in process: the pipeline of the mesh listener is the
//! pipeline of the public one plus the caller rule of `ROLE_SERVICE` tokens. A forwarder that
//! records the headers it receives stands for the upstream.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::{IntoResponse as _, Response};
use iam_application::{FreshnessState, RequestAuthorizer};
use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{
    AccessToken, AccessTokenParts, AccessTokenVerifier, AssignmentScope, AssignmentState,
    BootClock as _, BootInstant, CallerTokenRule, CompiledRoleSet, ForwardError, FreshnessRule,
    GrantStatus, HttpMethod, PermissionGrant, PolicyVersion, PolicyView, RevocationView, RoleId,
    RouteState, ServiceName, SubjectId, SubjectRef, TokenId, TokenMemo, TokenRepository,
    UpstreamForwarder, UpstreamState, UpstreamTarget,
};
use iam_infrastructure::{
    CachingTokenRepository, MokaTokenMemo, SnapshotRevocationView, TokenMemoSettings,
};
use rstest::rstest;
use service::bootstrap::gateway::pipeline::{ClientAddress, Pipeline, UnauditedCommands, router};
use shared_domain::{Clock, CommandBus, Uuid};
use test_support::access_token::FakeAccessTokenVerifier;
use test_support::boot_clock::FakeBootClock;
use test_support::clock::FixedClock;
use test_support::gateway_snapshot::{CountingPolicyView, GatewaySnapshot};
use test_support::id::SequenceUuidGenerator;
use test_support::route::{route, route_draft};
use test_support::seed::TestRng;
use test_support::upstream::upstream;
use tower::ServiceExt as _;

use super::{GOOD, HARD_BOUND, HOST, NOW, ROLE, USER, at, entry, token};

const CALLER_AUDIENCE: &str = "vilnacrm-iam";
const SERVICE: &str = "billing";
const SERVICE_TOKEN: &str = "service.token.value";
const SERVICE_WITHOUT_AUDIENCE: &str = "service.without.audience";
const SERVICE_LONG_LIVED: &str = "service.long.lived";
const MAX_SERVICE_LIFETIME: Duration = Duration::from_mins(15);
const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));

fn service_token(audiences: &[&str], lifetime: Duration) -> AccessToken {
    AccessToken::new(AccessTokenParts {
        subject: SubjectId::Service(ServiceName::new(SERVICE).unwrap()),
        session: None,
        token_id: TokenId::new("service-token-1").unwrap(),
        roles: vec!["ROLE_SERVICE".to_owned()],
        issued_at: at(NOW - 60),
        expires_at: at(NOW - 60).checked_add(lifetime).unwrap(),
    })
    .with_audiences(
        audiences
            .iter()
            .map(|audience| (*audience).to_owned())
            .collect(),
    )
}

fn verifier() -> FakeAccessTokenVerifier {
    FakeAccessTokenVerifier::new()
        .accepting(GOOD, token(USER, "session-1"))
        .accepting(
            SERVICE_TOKEN,
            service_token(&[CALLER_AUDIENCE, "other"], Duration::from_mins(10)),
        )
        .accepting(
            SERVICE_WITHOUT_AUDIENCE,
            service_token(&["other"], Duration::from_mins(10)),
        )
        .accepting(
            SERVICE_LONG_LIVED,
            service_token(&[CALLER_AUDIENCE], Duration::from_hours(2)),
        )
}

/// The snapshot of the upstream `users` with the route `GET /api/users/{id}`, whose key is held by
/// the user `USER` and by the service `billing`.
fn snapshot(rng: &mut TestRng) -> GatewaySnapshot {
    let users = UpstreamState::of(upstream(rng, "users", "users").parts());
    let role = RoleId::parse(ROLE).unwrap();
    let granted = CompiledRoleSet::compile([(
        PermissionGrant::parse("rest:users:GET /api/users/{}").unwrap(),
        GrantStatus::Active,
    )]);
    let users_route = route_draft(
        HOST,
        "/api/users/{id}",
        &[HttpMethod::Get],
        "users",
        users.id,
    );
    let assignment = || {
        vec![AssignmentState {
            role,
            scope: AssignmentScope::Global,
            expires_at_micros: None,
        }]
    };
    GatewaySnapshot::at(PolicyVersion::new(7).unwrap())
        .with_upstream(users)
        .with_route(RouteState::of(route(rng, &users_route).parts()))
        .with_catalogue(
            ServiceName::new("users").unwrap(),
            vec![entry("rest:users:GET /api/users/{}")],
        )
        .with_assignments(SubjectRef::user(Uuid::parse(USER).unwrap()), assignment())
        .with_assignments(
            SubjectRef::service(ServiceName::new(SERVICE).unwrap()),
            assignment(),
        )
        .with_role_set(role, granted)
}

/// What the upstream received.
#[derive(Debug, Default)]
struct Upstream {
    seen: Mutex<Vec<(String, HeaderMap)>>,
}

impl Upstream {
    fn received(&self) -> Vec<(String, HeaderMap)> {
        self.seen
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
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((request.uri().to_string(), request.headers().clone()));
        Ok(StatusCode::OK.into_response())
    }
}

/// A listener of the gateway: its router and the upstream behind it.
struct Listener {
    router: Router,
    upstream: Arc<Upstream>,
}

impl Listener {
    async fn send(&self, request: Request<Body>) -> Response {
        self.router.clone().oneshot(request).await.unwrap()
    }
}

/// The pipeline over one snapshot, as the mesh listener when `mesh` and as the public one
/// otherwise.
fn listener(mesh: bool) -> Listener {
    let mut rng = TestRng::from_env();
    let view = Arc::new(CountingPolicyView::serving(snapshot(&mut rng)));
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
    let authorizer = RequestAuthorizer::new(
        token_port,
        clock,
        Arc::new(SequenceUuidGenerator::starting_at(1)),
        commands,
    );
    let upstream = Arc::new(Upstream::default());
    let pipeline = Pipeline::new(
        policy,
        freshness,
        tokens,
        Arc::new(authorizer),
        Arc::<Upstream>::clone(&upstream),
    );
    let pipeline = if mesh {
        pipeline.with_service_callers(CallerTokenRule::new(
            CALLER_AUDIENCE.to_owned(),
            MAX_SERVICE_LIFETIME,
        ))
    } else {
        pipeline
    };
    Listener {
        router: router(pipeline),
        upstream,
    }
}

fn call(path: &str, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::get(path).header("host", HOST);
    if let Some(token) = token {
        builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    let mut request = builder.body(Body::empty()).unwrap();
    request
        .extensions_mut()
        .insert(ClientAddress::from(SocketAddr::new(PEER, 40_000)));
    request
}

fn text<'headers>(headers: &'headers HeaderMap, name: &str) -> Option<&'headers str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

#[tokio::test]
async fn a_service_with_the_caller_audience_reaches_the_upstream_as_a_service_principal() {
    let mesh = listener(true);

    let response = mesh.send(call("/api/users/1", Some(SERVICE_TOKEN))).await;

    assert_eq!(response.status(), StatusCode::OK);
    let received = mesh.upstream.received();
    let (uri, headers) = received.first().unwrap();
    assert_eq!(uri, "/api/users/1");
    assert_eq!(text(headers, "x-iam-subject"), Some(SERVICE));
    assert_eq!(text(headers, "x-iam-subject-kind"), Some("service"));
    assert_eq!(text(headers, "x-forwarded-for"), Some("10.1.2.3"));
}

#[tokio::test]
async fn a_user_token_forwarded_by_a_service_passes_the_mesh_listener_unchanged() {
    let mesh = listener(true);

    let response = mesh.send(call("/api/users/1", Some(GOOD))).await;

    assert_eq!(response.status(), StatusCode::OK);
    let received = mesh.upstream.received();
    let (_uri, headers) = received.first().unwrap();
    assert_eq!(text(headers, "x-iam-subject"), Some(USER));
    assert_eq!(text(headers, "x-iam-subject-kind"), Some("user"));
}

#[tokio::test]
async fn a_call_without_a_token_is_401_and_a_forged_principal_header_never_reaches_the_upstream() {
    let mesh = listener(true);
    let mut forged = call("/api/users/1", None);
    forged
        .headers_mut()
        .insert("x-iam-subject", "forged-subject".parse().unwrap());
    forged
        .headers_mut()
        .insert("x-iam-subject-kind", "service".parse().unwrap());

    let without_token = mesh.send(call("/api/users/1", None)).await;
    let forged_without_token = mesh.send(forged).await;

    assert_eq!(without_token.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(forged_without_token.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(mesh.upstream.received().len(), 0);
}

#[tokio::test]
async fn a_forged_principal_header_with_a_valid_token_is_replaced_by_the_gateway() {
    let mesh = listener(true);
    let mut forged = call("/api/users/1", Some(SERVICE_TOKEN));
    forged
        .headers_mut()
        .insert("x-iam-subject", "forged-subject".parse().unwrap());

    let response = mesh.send(forged).await;

    assert_eq!(response.status(), StatusCode::OK);
    let received = mesh.upstream.received();
    let (_uri, headers) = received.first().unwrap();
    assert_eq!(headers.get_all("x-iam-subject").iter().count(), 1);
    assert_eq!(text(headers, "x-iam-subject"), Some(SERVICE));
}

#[rstest]
#[case::lacking_the_caller_audience(SERVICE_WITHOUT_AUDIENCE)]
#[case::living_longer_than_the_service_token_lifetime(SERVICE_LONG_LIVED)]
#[tokio::test]
async fn a_service_token_failing_the_caller_rule_is_401_on_the_mesh_listener(#[case] token: &str) {
    let mesh = listener(true);

    let response = mesh.send(call("/api/users/1", Some(token))).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(mesh.upstream.received().len(), 0);
}

#[rstest]
#[case::user_token("/api/users/1", Some(GOOD))]
#[case::service_token("/api/users/1", Some(SERVICE_TOKEN))]
#[case::no_token("/api/users/1", None)]
#[case::no_route("/api/nothing", Some(GOOD))]
#[tokio::test]
async fn the_same_request_is_decided_and_forwarded_alike_by_both_listeners(
    #[case] path: &str,
    #[case] token: Option<&str>,
) {
    let public = listener(false);
    let mesh = listener(true);

    let from_public = public.send(call(path, token)).await;
    let from_mesh = mesh.send(call(path, token)).await;

    assert_eq!(from_public.status(), from_mesh.status());
    let sent_by_public = public.upstream.received();
    let sent_by_mesh = mesh.upstream.received();
    assert_eq!(sent_by_public.len(), sent_by_mesh.len());
    for ((public_uri, public_headers), (mesh_uri, mesh_headers)) in
        sent_by_public.iter().zip(&sent_by_mesh)
    {
        assert_eq!(public_uri, mesh_uri);
        let names = |headers: &HeaderMap| {
            let mut names: Vec<_> = headers
                .iter()
                .filter(|(name, _)| !matches!(name.as_str(), "x-request-id"))
                .map(|(name, value)| (name.as_str().to_owned(), value.clone()))
                .collect();
            names.sort_by(|left, right| left.0.cmp(&right.0));
            names
        };
        assert_eq!(names(public_headers), names(mesh_headers));
    }
}
