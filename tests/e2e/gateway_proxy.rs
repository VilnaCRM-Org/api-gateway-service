//! The in-process gateway of the proxy scenarios (Story 10.3): the production pipeline and
//! [`HyperUpstreamForwarder`] over a snapshot that the scenario describes, with static endpoints
//! that point at a fake upstream on a loopback socket. No database is involved: the decision and
//! the forwarding come from the snapshot alone.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::header::{AUTHORIZATION, COOKIE, ORIGIN};
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse as _, Response};
use http_body_util::BodyExt as _;
use iam_application::{EndpointDirectory, FreshnessState, RequestAuthorizer, ZoneSource};
use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{
    AccessToken, AccessTokenParts, AccessTokenVerifier, AssignmentScope, AssignmentState,
    BootClock as _, BootInstant, CatalogueEntryState, CompiledRoleSet, CorsDraft,
    EndpointConditions, EndpointParts, EndpointSlice, FreshnessRule, GrantStatus, HttpMethod,
    PermissionGrant, PolicyVersion, PolicyView, RevocationView, RoleId, RouteState, ServiceName,
    SessionId, SubjectId, SubjectRef, TokenId, TokenMemo, TokenRepository, UpstreamEndpoint,
    UpstreamState, WatchTarget,
};
use iam_infrastructure::{
    CachingTokenRepository, MokaTokenMemo, SnapshotRevocationView, TokenMemoSettings,
};
use service::bootstrap::gateway::pipeline::{Forwarder, Pipeline, UnauditedCommands, router};
use service::bootstrap::gateway::upstream::HyperUpstreamForwarder;
use shared_domain::{Clock, CommandBus, Uuid};
use test_support::access_token::FakeAccessTokenVerifier;
use test_support::boot_clock::FakeBootClock;
use test_support::clock::FixedClock;
use test_support::gateway_snapshot::{CountingPolicyView, GatewaySnapshot};
use test_support::id::SequenceUuidGenerator;
use test_support::rng::FakeRng;
use test_support::route::{route, route_draft};
use test_support::seed::TestRng;
use test_support::upstream::upstream;
use tokio::net::TcpListener;
use tower::ServiceExt as _;

/// The instant the pipeline sees as now, in seconds after the epoch.
const NOW: u64 = 1_800_000_000;

/// The hard bound of the freshness rule of the gateway.
const HARD_BOUND: Duration = Duration::from_secs(15);

/// What a scenario describes before the first request: one route and the subjects.
#[derive(Debug, Default)]
pub(crate) struct GatewayPlan {
    host: String,
    service: String,
    method: String,
    pattern: String,
    key: String,
    subjects: Vec<(String, Vec<String>)>,
    cors_origin: Option<String>,
}

impl GatewayPlan {
    /// The plan of a gateway with one route `method pattern` of `host` that the key `key` of the
    /// catalogue service `service` guards.
    pub(crate) fn route(host: &str, service: &str, method: &str, pattern: &str, key: &str) -> Self {
        Self {
            host: host.to_owned(),
            service: service.to_owned(),
            method: method.to_owned(),
            pattern: pattern.to_owned(),
            key: key.to_owned(),
            subjects: Vec::new(),
            cors_origin: None,
        }
    }

    /// Gives the route a CORS policy that allows `origin` with credentials for the method of the
    /// route.
    pub(crate) fn allow_origin(&mut self, origin: &str) {
        self.cors_origin = Some(origin.to_owned());
    }

    /// Adds the grant `key` to the subject `name`, which exists after this call.
    pub(crate) fn grant(&mut self, name: &str, key: &str) {
        if let Some((_, keys)) = self.subjects.iter_mut().find(|(known, _)| known == name) {
            keys.push(key.to_owned());
        } else {
            self.subjects.push((name.to_owned(), vec![key.to_owned()]));
        }
    }

    /// Adds the subject `name` without a key.
    pub(crate) fn without_key(&mut self, name: &str) {
        if self.subjects.iter().all(|(known, _)| known != name) {
            self.subjects.push((name.to_owned(), Vec::new()));
        }
    }
}

/// What the fake upstream saw: the number of requests that reached it.
#[derive(Debug, Clone, Default)]
struct Seen(Arc<AtomicUsize>);

async fn answer(State(seen): State<Seen>, body: Bytes) -> Response {
    seen.0.fetch_add(1, Ordering::SeqCst);
    (
        StatusCode::CREATED,
        [("x-upstream", "yes")],
        format!("upstream got {} bytes", body.len()),
    )
        .into_response()
}

/// The gateway of a scenario, with the counter of its fake upstream.
#[derive(Debug)]
pub(crate) struct GatewayHarness {
    router: Router,
    host: String,
    seen: Seen,
    tokens: Vec<String>,
}

/// What the gateway answered.
#[derive(Debug)]
pub(crate) struct GatewayReply {
    pub(crate) status: u16,
    pub(crate) headers: axum::http::HeaderMap,
    pub(crate) body: String,
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .expect("a representable instant")
}

/// The credential of the subject at `index`.
fn credential(name: &str) -> String {
    format!("{name}.token.value")
}

fn user_id(index: usize) -> Uuid {
    Uuid::parse(&format!(
        "3d9b7c1e-5a2f-4e8d-b6c0-{:012x}",
        index.saturating_add(1)
    ))
    .expect("a valid user id")
}

fn role_id(index: usize) -> RoleId {
    RoleId::parse(&format!(
        "0190f2a8-7b3c-7d4e-8f10-{:012x}",
        index.saturating_add(1)
    ))
    .expect("a valid role id")
}

fn token_of(index: usize) -> AccessToken {
    AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(user_id(index)),
        session: Some(SessionId::new(&format!("session-{index}")).expect("a session")),
        token_id: TokenId::new(&format!("token-{index}")).expect("a token id"),
        roles: vec!["ROLE_USER".to_owned()],
        issued_at: at(NOW - 60),
        expires_at: at(NOW + 900),
    })
}

fn parse_method(method: &str) -> HttpMethod {
    match method {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "PATCH" => HttpMethod::Patch,
        "DELETE" => HttpMethod::Delete,
        other => panic!("unsupported method {other}"),
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "an end-to-end scenario serves its fake upstream on a free loopback port"
)]
async fn bound() -> TcpListener {
    TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a free loopback port")
}

/// The snapshot of the plan: its upstream, its route, a catalogue with the key of the route and the
/// role of every subject with the keys it holds.
fn snapshot(plan: &GatewayPlan) -> GatewaySnapshot {
    let mut rng = TestRng::from_env();
    let upstream_state =
        UpstreamState::of(upstream(&mut rng, &plan.service, &plan.service).parts());
    let mut draft = route_draft(
        &plan.host,
        &plan.pattern,
        &[parse_method(&plan.method)],
        &plan.service,
        upstream_state.id,
    );
    draft.cors = plan.cors_origin.as_ref().map(|origin| CorsDraft {
        origins: vec![origin.clone()],
        methods: vec![parse_method(&plan.method)],
        headers: vec!["Content-Type".to_owned()],
        allow_credentials: true,
        max_age_seconds: 600,
    });
    let mut snapshot = GatewaySnapshot::at(PolicyVersion::new(7).expect("a version"))
        .with_upstream(upstream_state)
        .with_route(RouteState::of(route(&mut rng, &draft).parts()))
        .with_catalogue(
            ServiceName::new(&plan.service).expect("a service name"),
            vec![CatalogueEntryState::untyped(
                plan.key.clone(),
                [false, false],
            )],
        );
    for (index, (_, keys)) in plan.subjects.iter().enumerate() {
        let grants = keys.iter().map(|key| {
            (
                PermissionGrant::parse(key).expect("a permission key"),
                GrantStatus::Active,
            )
        });
        snapshot = snapshot
            .with_assignments(
                SubjectRef::user(user_id(index)),
                vec![AssignmentState {
                    role: role_id(index),
                    scope: AssignmentScope::Global,
                    expires_at_micros: None,
                }],
            )
            .with_role_set(role_id(index), CompiledRoleSet::compile(grants));
    }
    snapshot
}

/// The directory whose only endpoint for the service of the plan is `address`.
fn directory_of(plan: &GatewayPlan, address: SocketAddr) -> EndpointDirectory {
    let directory = EndpointDirectory::new(ZoneSource {
        peers: WatchTarget {
            namespace: "platform".to_owned(),
            service: "iam-gateway-peers".to_owned(),
        },
        pod: None,
        explicit: None,
    });
    directory.replace(
        &WatchTarget {
            namespace: "platform".to_owned(),
            service: format!("{}-service", plan.service),
        },
        vec![EndpointSlice {
            name: "slice".to_owned(),
            endpoints: vec![UpstreamEndpoint::new(EndpointParts {
                address: address.ip().to_string(),
                port: address.port(),
                zone: None,
                pod: None,
                conditions: EndpointConditions::healthy(),
            })],
        }],
    );
    directory
}

/// The router of the production pipeline over `view` that forwards through `forwarder` and
/// verifies the credentials of `plan`.
fn pipeline_over(
    plan: &GatewayPlan,
    view: &Arc<CountingPolicyView>,
    forwarder: Arc<Forwarder>,
) -> Router {
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
        PolicyVersion::new(7).expect("a version"),
    );
    let clock: Arc<dyn Clock> = Arc::new(FixedClock::at(at(NOW)));
    let policy: Arc<dyn PolicyView> = Arc::<CountingPolicyView>::clone(view);
    let verifier = plan.subjects.iter().enumerate().fold(
        FakeAccessTokenVerifier::new(),
        |verifier, (index, (name, _))| verifier.accepting(&credential(name), token_of(index)),
    );
    let verifier: Arc<dyn AccessTokenVerifier> = Arc::new(verifier);
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
    router(Pipeline::new(
        policy,
        freshness,
        tokens,
        Arc::new(authorizer),
        forwarder,
    ))
}

impl GatewayHarness {
    /// Serves the fake upstream and builds the gateway of `plan` in front of it.
    pub(crate) async fn start(plan: &GatewayPlan) -> Self {
        let seen = Seen::default();
        let fake = Router::new().fallback(answer).with_state(seen.clone());
        let listener = bound().await;
        let address = listener.local_addr().expect("a bound address");
        drop(tokio::spawn(
            async move { axum::serve(listener, fake).await },
        ));
        let directory = directory_of(plan, address);
        let forwarder: Arc<Forwarder> = Arc::new(HyperUpstreamForwarder::new(
            directory.view(),
            true,
            Arc::new(FakeRng::seeded(1)),
        ));
        let view = Arc::new(CountingPolicyView::serving(snapshot(plan)));
        Self {
            router: pipeline_over(plan, &view, forwarder),
            host: plan.host.clone(),
            seen,
            tokens: plan.subjects.iter().map(|(name, _)| name.clone()).collect(),
        }
    }

    /// How many requests reached the fake upstream.
    pub(crate) fn upstream_requests(&self) -> usize {
        self.seen.0.load(Ordering::SeqCst)
    }

    /// Sends the request of the subject `name` through the gateway.
    ///
    /// # Panics
    ///
    /// When the plan holds no subject of that name.
    pub(crate) async fn send(&self, name: &str, method: &str, path: &str) -> GatewayReply {
        let bearer = format!("Bearer {}", credential(name));
        self.deliver(name, method, path, &[(AUTHORIZATION.as_str(), bearer)])
            .await
    }

    /// Sends the request of the subject `name` the way a browser of the page at `origin` does: the
    /// session cookie instead of a bearer token, and the `Origin` header.
    ///
    /// # Panics
    ///
    /// When the plan holds no subject of that name.
    pub(crate) async fn send_from_browser(
        &self,
        name: &str,
        method: &str,
        path: &str,
        origin: &str,
    ) -> GatewayReply {
        let cookie = format!("__Host-auth_token={}", credential(name));
        self.deliver(
            name,
            method,
            path,
            &[
                (COOKIE.as_str(), cookie),
                (ORIGIN.as_str(), origin.to_owned()),
            ],
        )
        .await
    }

    async fn deliver(
        &self,
        name: &str,
        method: &str,
        path: &str,
        headers: &[(&str, String)],
    ) -> GatewayReply {
        assert!(
            self.tokens.iter().any(|known| known == name),
            "the scenario names no subject {name}"
        );
        let request = headers
            .iter()
            .fold(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("host", &self.host),
                |builder, (header, value)| builder.header(*header, value),
            )
            .body(Body::empty())
            .expect("a valid request");
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("infallible");
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("a body")
            .to_bytes();
        GatewayReply {
            status,
            headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }
}
