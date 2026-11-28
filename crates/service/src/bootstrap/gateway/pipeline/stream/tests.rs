use std::time::{Duration, SystemTime};

use axum::http::Request;
use iam_application::{GraphQlRequestAnalyzer, ParseBudgetSettings};
use iam_domain::{
    AccessToken, AccessTokenParts, AssignmentScope, CatalogueEntryState, CompiledRoleSet,
    EnforcementMode, GlobalRevocationState, GrantStatus, HttpMethod, PermissionGrant,
    PolicyVersion, RoleId, RouteFlag, RouteFlags, ServiceName, SessionId, TokenId, TokenIdentity,
    UserRevocationState,
};
use iam_infrastructure::{DocumentCacheSettings, MokaDocumentCache};
use shared_domain::Uuid;
use test_support::clock::FixedClock;
use test_support::gateway_snapshot::{CountingPolicyView, GatewaySnapshot};
use test_support::id::SequenceUuidGenerator;
use test_support::route::{route, route_draft};
use test_support::seed::TestRng;
use test_support::token::FakeTokenRepository;
use test_support::upstream::upstream;

use super::*;
use crate::bootstrap::gateway::edge::{Edge, EdgeLimits};
use crate::bootstrap::gateway::pipeline::UnauditedCommands;
use crate::bootstrap::gateway::streams::StreamSettings;

const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";
const ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890cd";
const OTHER_ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ce";
const NOW: u64 = 1_800_000_000;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn micros(seconds: u64) -> Option<i64> {
    i64::try_from(seconds.saturating_mul(1_000_000)).ok()
}

fn principal() -> Principal {
    Principal::from(TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(Uuid::parse(USER).unwrap()),
        session: Some(SessionId::new("session-1").unwrap()),
        token_id: TokenId::new("jti-1").unwrap(),
        roles: vec!["ROLE_USER".to_owned()],
        issued_at: at(NOW - 60),
        expires_at: at(NOW + 900),
    })))
}

fn assignment(role: &str, expires_at_seconds: Option<u64>) -> AssignmentState {
    AssignmentState {
        role: RoleId::parse(role).unwrap(),
        scope: AssignmentScope::Global,
        expires_at_micros: expires_at_seconds.and_then(micros),
    }
}

fn snapshot_of(
    held: Vec<AssignmentState>,
    streaming: bool,
) -> (Arc<dyn PolicySnapshot>, RouteState) {
    let (view, state) = view_of(held, streaming);
    (view.current().unwrap(), state)
}

fn view_of(held: Vec<AssignmentState>, streaming: bool) -> (Arc<dyn PolicyView>, RouteState) {
    view_revoking(held, streaming, |snapshot| snapshot)
}

/// The view of [`view_of`] over a snapshot that `revoke` has changed.
fn view_revoking(
    held: Vec<AssignmentState>,
    streaming: bool,
    revoke: impl FnOnce(GatewaySnapshot) -> GatewaySnapshot,
) -> (Arc<dyn PolicyView>, RouteState) {
    let mut rng = TestRng::from_env();
    let users = iam_domain::UpstreamState::of(upstream(&mut rng, "users", "users").parts());
    let mut draft = route_draft(
        "api.example.test",
        "/api/stream",
        &[HttpMethod::Get],
        "users",
        users.id,
    );
    draft.flags = RouteFlags::default().with(RouteFlag::Streaming, streaming);
    draft.enforcement = EnforcementMode::Enforce;
    let state = RouteState::of(route(&mut rng, &draft).parts());
    let granted = CompiledRoleSet::compile(
        [
            "rest:users:GET /api/stream",
            "gql:users:Subscription.orderUpdated",
        ]
        .map(|key| (PermissionGrant::parse(key).unwrap(), GrantStatus::Active)),
    );
    let snapshot = GatewaySnapshot::at(PolicyVersion::new(7).unwrap())
        .with_upstream(users)
        .with_route(state.clone())
        .with_catalogue(
            ServiceName::new("users").unwrap(),
            vec![
                CatalogueEntryState::untyped(
                    "rest:users:GET /api/stream".to_owned(),
                    [false, false],
                ),
                CatalogueEntryState {
                    key: "gql:users:Subscription.orderUpdated".to_owned(),
                    sensitive: false,
                    audit_always: false,
                    return_type: Some("String".to_owned()),
                    possible_types: Vec::new(),
                },
            ],
        )
        .with_assignments(SubjectRef::user(Uuid::parse(USER).unwrap()), held)
        .with_role_set(RoleId::parse(ROLE).unwrap(), granted);
    (
        Arc::new(CountingPolicyView::serving(revoke(snapshot))),
        state,
    )
}

fn parts(claims: Option<Arc<SubjectClaims>>) -> Parts {
    let mut request = Request::get("/api/stream")
        .header("host", "Api.Example.Test:8443")
        .body(())
        .unwrap();
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    request.into_parts().0
}

fn streams(per_subject: usize) -> Arc<Streams> {
    Streams::new(
        StreamSettings {
            idle_timeout: Duration::from_mins(5),
            per_subject,
        },
        Arc::new(FixedClock::at(at(NOW))),
    )
}

fn opening<'a>(
    parts: &'a Parts,
    route: &'a RouteState,
    snapshot: &'a Arc<dyn PolicySnapshot>,
    principal: Option<&'a Principal>,
) -> Opening<'a> {
    Opening {
        parts,
        route,
        snapshot,
        principal,
        key: Some("rest:users:GET /api/stream"),
    }
}

#[test]
fn the_earliest_expiry_that_is_still_ahead_is_the_one_to_look_at() {
    let (snapshot, _route) = snapshot_of(
        vec![
            assignment(ROLE, None),
            assignment(ROLE, Some(NOW + 600)),
            assignment(ROLE, Some(NOW + 300)),
            assignment(ROLE, Some(NOW - 5)),
            assignment(OTHER_ROLE, Some(NOW + 10)),
        ],
        true,
    );

    let earliest = earliest_expiry(&snapshot, &principal(), at(NOW));

    assert_eq!(earliest, Some(at(NOW + 300)));
}

#[test]
fn assignments_that_never_expire_leave_no_expiry_to_look_at() {
    let (snapshot, _route) = snapshot_of(vec![assignment(ROLE, None)], true);

    assert_eq!(earliest_expiry(&snapshot, &principal(), at(NOW)), None);
}

#[test]
fn a_stamp_before_1970_is_the_epoch_and_is_never_ahead() {
    let state = AssignmentState {
        expires_at_micros: Some(-1),
        ..assignment(ROLE, None)
    };

    assert_eq!(expiry_of(&state), Some(SystemTime::UNIX_EPOCH));
}

#[test]
fn a_streaming_route_registers_the_stream_with_what_authorized_it() {
    let (snapshot, route) = snapshot_of(
        vec![assignment(ROLE, Some(NOW + 600)), assignment(ROLE, None)],
        true,
    );
    let streams = streams(4);
    let request = parts(None);
    let caller = principal();

    let handle = register(
        Some(&streams),
        &opening(&request, &route, &snapshot, Some(&caller)),
    )
    .unwrap()
    .unwrap();

    let record = streams.registry().record(handle.id()).unwrap();
    assert_eq!(record.subject.as_deref(), Some(USER));
    assert_eq!(record.session.as_deref(), Some("session-1"));
    assert_eq!(record.required_keys, vec!["rest:users:GET /api/stream"]);
    assert_eq!(record.scope, "global");
    assert_eq!(record.token_expires_at, Some(at(NOW + 900)));
    assert_eq!(record.assignment_expires_at, Some(at(NOW + 600)));
    assert_eq!(record.version, 7);
    assert_eq!(streams.registry().held_by_subject(USER), 1);
    assert_eq!(streams.registry().held_by_session("session-1"), 1);
}

#[test]
fn the_grant_names_the_host_the_method_and_the_path_to_decide_again() {
    let (snapshot, route) = snapshot_of(Vec::new(), true);
    let request = parts(None);
    let caller = principal();

    let grant = grant_of(&opening(&request, &route, &snapshot, Some(&caller)));

    assert_eq!(grant.host, "api.example.test");
    assert_eq!(grant.method, HttpMethod::Get);
    assert_eq!(grant.path, "/api/stream");
    assert!(grant.principal.is_some());
}

#[test]
fn a_route_that_is_not_streaming_registers_nothing() {
    let (snapshot, route) = snapshot_of(Vec::new(), false);
    let streams = streams(4);
    let request = parts(None);
    let caller = principal();

    let handle = register(
        Some(&streams),
        &opening(&request, &route, &snapshot, Some(&caller)),
    )
    .unwrap();

    assert!(handle.is_none());
    assert!(streams.registry().is_empty());
}

#[test]
fn a_pipeline_without_streams_registers_nothing() {
    let (snapshot, route) = snapshot_of(Vec::new(), true);
    let request = parts(None);

    let handle = register(None, &opening(&request, &route, &snapshot, None)).unwrap();

    assert!(handle.is_none());
}

#[test]
fn an_anonymous_stream_has_no_subject_and_no_cap() {
    let (snapshot, route) = snapshot_of(Vec::new(), true);
    let streams = streams(1);
    let request = parts(None);

    let first = register(Some(&streams), &opening(&request, &route, &snapshot, None)).unwrap();
    let second = register(Some(&streams), &opening(&request, &route, &snapshot, None)).unwrap();

    assert!(first.is_some() && second.is_some());
    let record = streams.registry().record(first.unwrap().id()).unwrap();
    assert_eq!(record.subject, None);
    assert_eq!(record.token_expires_at, None);
    assert_eq!(record.assignment_expires_at, None);
}

#[test]
fn a_subject_at_its_stream_cap_is_refused_before_the_upgrade() {
    let (snapshot, route) = snapshot_of(Vec::new(), true);
    let streams = streams(1);
    let request = parts(None);
    let caller = principal();
    let held = register(
        Some(&streams),
        &opening(&request, &route, &snapshot, Some(&caller)),
    )
    .unwrap();

    let refused = register(
        Some(&streams),
        &opening(&request, &route, &snapshot, Some(&caller)),
    );

    assert_eq!(refused.unwrap_err(), Refusal::ConnectionLimit);
    assert_eq!(streams.registry().len(), 1);
    drop(held);
}

#[test]
fn the_stream_keeps_the_connection_slots_of_its_subject_until_it_ends() {
    let (snapshot, route) = snapshot_of(Vec::new(), true);
    let edge = Edge::new(
        EdgeLimits {
            connections_per_subject: 1,
            ..EdgeLimits::default()
        },
        false,
        None,
    );
    let claims = edge.claims();
    assert!(claims.claim(USER));
    let streams = streams(4);
    let request = parts(Some(Arc::clone(&claims)));
    let caller = principal();
    let handle = register(
        Some(&streams),
        &opening(&request, &route, &snapshot, Some(&caller)),
    )
    .unwrap();
    drop((claims, request));

    assert!(!edge.claims().claim(USER));
    drop(handle);
    assert!(edge.claims().claim(USER));
}

#[test]
fn the_registration_travels_to_the_forwarder_as_a_request_extension() {
    let (snapshot, route) = snapshot_of(Vec::new(), true);
    let streams = streams(4);
    let mut request = parts(None);
    let handle = register(Some(&streams), &opening(&request, &route, &snapshot, None)).unwrap();

    attach(&mut request, handle);

    assert!(request.extensions.get::<Arc<StreamHandle>>().is_some());
    attach(&mut parts(None), None);
}

fn redecision(view: Arc<dyn PolicyView>) -> PipelineRedecision {
    let clock: Arc<dyn Clock> = Arc::new(FixedClock::at(at(NOW)));
    let authorizer = RequestAuthorizer::new(
        Arc::new(FakeTokenRepository::new()),
        Arc::clone(&clock),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
        Arc::new(UnauditedCommands),
    );
    PipelineRedecision::new(view, Arc::new(authorizer), clock)
}

fn anonymous_grant() -> Grant {
    Grant {
        principal: None,
        host: "api.example.test".to_owned(),
        method: HttpMethod::Get,
        path: "/api/stream".to_owned(),
        operation: None,
    }
}

#[tokio::test]
async fn an_anonymous_stream_stays_allowed_while_its_route_exists_and_has_no_expiry() {
    let (view, _route) = view_of(Vec::new(), true);

    let decided = redecision(view).decide(&anonymous_grant()).await;

    assert_eq!(decided, Revalidated::Allowed { next_expiry: None });
}

#[tokio::test]
async fn a_stream_whose_route_is_gone_is_denied_again() {
    let (view, _route) = view_of(Vec::new(), true);
    let grant = Grant {
        path: "/api/gone".to_owned(),
        ..anonymous_grant()
    };

    let decided = redecision(view).decide(&grant).await;

    assert_eq!(decided, Revalidated::Denied);
}

#[test]
fn the_assignments_of_a_service_principal_are_read_under_its_service_name() {
    let name = ServiceName::new("billing").unwrap();
    let principal = Principal::from(TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject: SubjectId::Service(name.clone()),
        session: None,
        token_id: TokenId::new("jti-2").unwrap(),
        roles: Vec::new(),
        issued_at: at(NOW - 60),
        expires_at: at(NOW + 900),
    })));
    let service_view = GatewaySnapshot::at(PolicyVersion::new(7).unwrap())
        .with_assignments(
            SubjectRef::service(name),
            vec![assignment(ROLE, Some(NOW + 300))],
        )
        .with_role_set(
            RoleId::parse(ROLE).unwrap(),
            CompiledRoleSet::compile([(
                PermissionGrant::parse("rest:users:GET /api/stream").unwrap(),
                GrantStatus::Active,
            )]),
        );
    let held: Arc<dyn PolicySnapshot> =
        CountingPolicyView::serving(service_view).current().unwrap();

    assert_eq!(
        earliest_expiry(&held, &principal, at(NOW)),
        Some(at(NOW + 300))
    );
}

#[tokio::test]
async fn a_stream_is_denied_again_while_the_gateway_has_no_snapshot() {
    let view: Arc<dyn PolicyView> = Arc::new(CountingPolicyView::empty());

    let decided = redecision(view).decide(&anonymous_grant()).await;

    assert_eq!(decided, Revalidated::Denied);
}

#[tokio::test]
async fn a_stream_whose_path_is_malformed_is_denied_again() {
    let (view, _route) = view_of(Vec::new(), true);
    let grant = Grant {
        path: "/api/%zz".to_owned(),
        ..anonymous_grant()
    };

    let decided = redecision(view).decide(&grant).await;

    assert_eq!(decided, Revalidated::Denied);
}

fn grant_of_the_user() -> Grant {
    Grant {
        principal: Some(principal()),
        ..anonymous_grant()
    }
}

#[tokio::test]
async fn a_stream_of_a_caller_the_rule_still_allows_gets_the_next_expiry_to_look_at() {
    let (view, _route) = view_of(vec![assignment(ROLE, Some(NOW + 300))], true);

    let decided = redecision(view).decide(&grant_of_the_user()).await;

    assert_eq!(
        decided,
        Revalidated::Allowed {
            next_expiry: Some(at(NOW + 300))
        }
    );
}

#[tokio::test]
async fn a_stream_of_a_caller_the_rule_no_longer_allows_is_denied_again() {
    let (view, _route) = view_of(Vec::new(), true);

    let decided = redecision(view).decide(&grant_of_the_user()).await;

    assert_eq!(decided, Revalidated::Denied);
}

fn allowed_by_role() -> Vec<AssignmentState> {
    vec![assignment(ROLE, None)]
}

fn user_cutoff(seconds: u64) -> UserRevocationState {
    UserRevocationState {
        user: Uuid::parse(USER).unwrap(),
        tokens_valid_after_micros: micros(seconds).unwrap(),
        prune_after_micros: micros(seconds.saturating_add(3_600)).unwrap(),
    }
}

#[tokio::test]
async fn a_stream_whose_session_was_revoked_is_denied_again() {
    let (view, _route) = view_revoking(allowed_by_role(), true, |snapshot| {
        snapshot.with_revoked_session(SessionId::new("session-1").unwrap())
    });

    let decided = redecision(view).decide(&grant_of_the_user()).await;

    assert_eq!(decided, Revalidated::Denied);
}

#[tokio::test]
async fn a_stream_whose_token_was_issued_before_the_user_cutoff_is_denied_again() {
    let (view, _route) = view_revoking(allowed_by_role(), true, |snapshot| {
        snapshot.with_user_cutoff(user_cutoff(NOW - 30))
    });

    let decided = redecision(view).decide(&grant_of_the_user()).await;

    assert_eq!(decided, Revalidated::Denied);
}

#[tokio::test]
async fn a_stream_whose_token_was_issued_after_the_user_cutoff_stays_allowed() {
    let (view, _route) = view_revoking(allowed_by_role(), true, |snapshot| {
        snapshot.with_user_cutoff(user_cutoff(NOW - 120))
    });

    let decided = redecision(view).decide(&grant_of_the_user()).await;

    assert_eq!(decided, Revalidated::Allowed { next_expiry: None });
}

#[tokio::test]
async fn a_stream_whose_token_was_issued_before_the_global_cutoff_is_denied_again() {
    let (view, _route) = view_revoking(allowed_by_role(), true, |snapshot| {
        snapshot.with_global_cutoff(GlobalRevocationState {
            tokens_valid_after_micros: micros(NOW - 30).unwrap(),
        })
    });

    let decided = redecision(view).decide(&grant_of_the_user()).await;

    assert_eq!(decided, Revalidated::Denied);
}

#[tokio::test]
async fn an_anonymous_stream_ignores_the_revocation_sets() {
    let (view, _route) = view_revoking(Vec::new(), true, |snapshot| {
        snapshot.with_global_cutoff(GlobalRevocationState {
            tokens_valid_after_micros: micros(NOW + 30).unwrap(),
        })
    });

    let decided = redecision(view).decide(&anonymous_grant()).await;

    assert_eq!(decided, Revalidated::Allowed { next_expiry: None });
}

#[test]
fn the_published_version_is_the_one_of_the_snapshot_and_none_without_a_snapshot() {
    let (view, _route) = view_of(Vec::new(), true);
    let empty: Arc<dyn PolicyView> = Arc::new(CountingPolicyView::empty());

    assert_eq!(redecision(view).published(), Some(7));
    assert_eq!(redecision(empty).published(), None);
}

#[test]
fn the_stream_records_the_route_and_the_service_it_was_opened_on() {
    let (snapshot, route) = snapshot_of(vec![assignment(ROLE, None)], true);
    let streams = streams(4);
    let request = parts(None);
    let caller = principal();

    let handle = register(
        Some(&streams),
        &opening(&request, &route, &snapshot, Some(&caller)),
    )
    .unwrap()
    .unwrap();

    let record = streams.registry().record(handle.id()).unwrap();
    assert_eq!(record.route, Some(route.id));
    assert_eq!(record.service.as_ref(), Some(route.fields.service()));
}

#[tokio::test]
async fn the_check_after_registration_costs_nothing_without_a_stream() {
    let streams = streams(4);

    admit(None, None).await;
    admit(Some(&streams), None).await;

    assert!(streams.registry().is_empty());
}

#[tokio::test]
async fn a_stream_authorized_on_the_published_version_survives_the_check_after_registration() {
    let (view, route) = view_of(vec![assignment(ROLE, None)], true);
    let snapshot = view.current().unwrap();
    let streams = streams(4);
    streams.install(Arc::new(redecision(view)));
    let request = parts(None);
    let caller = principal();
    let handle = register(
        Some(&streams),
        &opening(&request, &route, &snapshot, Some(&caller)),
    )
    .unwrap()
    .unwrap();

    admit(Some(&streams), Some(&handle)).await;

    assert_eq!(streams.registry().len(), 1);
}

#[tokio::test]
async fn a_stream_whose_cutoff_cannot_be_read_is_denied_again() {
    let (view, _route) = view_revoking(allowed_by_role(), true, |snapshot| {
        snapshot.with_global_cutoff(GlobalRevocationState {
            tokens_valid_after_micros: -1,
        })
    });

    let decided = redecision(view).decide(&grant_of_the_user()).await;

    assert_eq!(decided, Revalidated::Denied);
}

#[tokio::test]
async fn an_operation_that_no_analyzer_can_decide_is_denied_again() {
    let (view, _route) = view_of(allowed_by_role(), true);
    let grant = Grant {
        operation: Some(Arc::new(iam_application::GraphQlOperation {
            document: "subscription { orderUpdated }".to_owned(),
            operation_name: None,
        })),
        ..grant_of_the_user()
    };

    let decided = redecision(view).decide(&grant).await;

    assert_eq!(decided, Revalidated::Denied);
}

#[tokio::test]
async fn a_stream_without_an_operation_is_decided_on_its_route_alone() {
    let (view, _route) = view_of(allowed_by_role(), true);

    let decided = redecision(view).decide(&grant_of_the_user()).await;

    assert_eq!(decided, Revalidated::Allowed { next_expiry: None });
}

fn redecision_of_documents(view: Arc<dyn PolicyView>) -> PipelineRedecision {
    let clock: Arc<dyn Clock> = Arc::new(FixedClock::at(at(NOW)));
    let cache = Arc::new(MokaDocumentCache::new(DocumentCacheSettings {
        capacity_bytes: 1 << 20,
        time_to_idle: Duration::from_mins(1),
    }));
    let authorizer = RequestAuthorizer::new(
        Arc::new(FakeTokenRepository::new()),
        Arc::clone(&clock),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
        Arc::new(UnauditedCommands),
    )
    .with_graphql(Arc::new(GraphQlRequestAnalyzer::new(
        cache,
        ParseBudgetSettings::default(),
    )));
    PipelineRedecision::new(view, Arc::new(authorizer), clock)
}

fn grant_of_the_operation(document: &str) -> Grant {
    Grant {
        operation: Some(Arc::new(iam_application::GraphQlOperation {
            document: document.to_owned(),
            operation_name: None,
        })),
        ..grant_of_the_user()
    }
}

#[tokio::test]
async fn an_operation_the_policy_still_allows_keeps_its_stream_allowed() {
    let (view, _route) = view_of(allowed_by_role(), true);
    let grant = grant_of_the_operation("subscription { orderUpdated }");

    let decided = redecision_of_documents(view).decide(&grant).await;

    assert_eq!(decided, Revalidated::Allowed { next_expiry: None });
}

#[tokio::test]
async fn an_operation_the_policy_no_longer_allows_is_denied_again() {
    let (view, _route) = view_of(allowed_by_role(), true);
    let grant = grant_of_the_operation("subscription { paymentUpdated }");

    let decided = redecision_of_documents(view).decide(&grant).await;

    assert_eq!(decided, Revalidated::Denied);
}
