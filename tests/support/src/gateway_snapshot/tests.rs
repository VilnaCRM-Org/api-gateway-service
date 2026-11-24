use iam_domain::{
    AssignmentScope, AssignmentState, CatalogueEntryState, CompiledRoleSet, GlobalRevocationState,
    HttpMethod, PolicySnapshot as _, PolicyVersion, PolicyView as _, RoleId, RouteHost, RouteState,
    ServiceName, SessionId, SubjectRef, UpstreamName, UpstreamState, UserRevocationState,
};
use shared_domain::Uuid;

use super::{CountingPolicyView, GatewaySnapshot};
use crate::route::{route, route_draft};
use crate::seed::TestRng;
use crate::unit_of_work::uuid_v7;
use crate::upstream::upstream;

fn nil() -> Uuid {
    Uuid::parse("00000000-0000-0000-0000-000000000000").unwrap()
}

fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

fn snapshot(rng: &mut TestRng) -> (GatewaySnapshot, UpstreamState, RouteState) {
    let stored = upstream(rng, "users", "users");
    let upstream_state = UpstreamState::of(stored.parts());
    let draft = route_draft(
        "api.example.test",
        "/api/users/{id}",
        &[HttpMethod::Get],
        "users",
        upstream_state.id,
    );
    let route_state = RouteState::of(route(rng, &draft).parts());
    let snapshot = GatewaySnapshot::at(version(4))
        .with_upstream(upstream_state.clone())
        .with_route(route_state.clone());
    (snapshot, upstream_state, route_state)
}

#[test]
fn a_route_matches_its_host_method_and_the_segments_of_its_pattern() {
    let mut rng = TestRng::from_env();
    let (snapshot, _upstream, route_state) = snapshot(&mut rng);
    let host = RouteHost::new("api.example.test").unwrap();

    let found = snapshot.route(&host, HttpMethod::Get, "/api/users/7");

    assert_eq!(found, Some(&route_state));
    assert!(
        snapshot
            .route(&host, HttpMethod::Post, "/api/users/7")
            .is_none()
    );
    assert!(
        snapshot
            .route(&host, HttpMethod::Get, "/api/users")
            .is_none()
    );
    assert!(
        snapshot
            .route(&host, HttpMethod::Get, "/api/users/7/x")
            .is_none()
    );
    assert!(
        snapshot
            .route(&host, HttpMethod::Get, "/api/orders/7")
            .is_none()
    );
    let other = RouteHost::new("other.example.test").unwrap();
    assert!(
        snapshot
            .route(&other, HttpMethod::Get, "/api/users/7")
            .is_none()
    );
}

#[test]
fn a_catch_all_matches_every_remaining_segment() {
    let mut rng = TestRng::from_env();
    let stored = upstream(&mut rng, "users", "users");
    let draft = route_draft(
        "api.example.test",
        "/files/{rest:*}",
        &[HttpMethod::Get],
        "users",
        UpstreamState::of(stored.parts()).id,
    );
    let snapshot =
        GatewaySnapshot::at(version(1)).with_route(RouteState::of(route(&mut rng, &draft).parts()));
    let host = RouteHost::new("api.example.test").unwrap();

    assert!(
        snapshot
            .route(&host, HttpMethod::Get, "/files/a/b/c")
            .is_some()
    );
    assert!(snapshot.route(&host, HttpMethod::Get, "/files").is_none());
}

#[test]
fn a_snapshot_answers_with_what_it_was_given_and_nothing_else() {
    let mut rng = TestRng::from_env();
    let (snapshot, upstream_state, _route) = snapshot(&mut rng);
    let subject = SubjectRef::user(uuid_v7(&mut rng));
    let role = RoleId::from_uuid(uuid_v7(&mut rng));
    let service = ServiceName::new("users").unwrap();
    let session = SessionId::new("session-1").unwrap();
    let user = uuid_v7(&mut rng);
    let snapshot = snapshot
        .with_assignments(
            subject.clone(),
            vec![AssignmentState {
                role,
                scope: AssignmentScope::Global,
                expires_at_micros: None,
            }],
        )
        .with_role_set(role, CompiledRoleSet::default())
        .with_catalogue(
            service.clone(),
            vec![CatalogueEntryState {
                key: "rest:users:GET /api/users".to_owned(),
                sensitive: false,
                audit_always: false,
            }],
        )
        .with_revoked_session(session.clone())
        .with_user_cutoff(UserRevocationState {
            user,
            tokens_valid_after_micros: 1,
            prune_after_micros: 2,
        })
        .with_global_cutoff(GlobalRevocationState {
            tokens_valid_after_micros: 3,
        });
    let name = UpstreamName::new("users").unwrap();

    assert_eq!(snapshot.version(), version(4));
    assert_eq!(snapshot.freshness_proof().version, version(4));
    assert_eq!(snapshot.upstream(&name), Some(&upstream_state));
    assert_eq!(
        snapshot.upstream_by_id(upstream_state.id),
        Some(&upstream_state)
    );
    assert!(
        snapshot
            .upstream(&UpstreamName::new("other").unwrap())
            .is_none()
    );
    assert_eq!(snapshot.assignments(&subject).len(), 1);
    assert!(snapshot.role_set(role).is_some());
    assert_eq!(snapshot.catalogue(&service).map(<[_]>::len), Some(1));
    assert!(snapshot.session_revoked(&session));
    assert!(snapshot.user_cutoff(user).is_some());
    assert!(snapshot.global_cutoff().is_some());
    assert_eq!(snapshot.accounted_bytes(), 0);
    assert_eq!(snapshot.digest(), snapshot.derived_hash());
    assert_eq!(snapshot.log_epoch(), iam_domain::LogEpoch::ZERO);
    let no_subjects: [SubjectRef; 0] = [];
    assert_eq!(snapshot.subjects_of_role(role), no_subjects);
    assert!(
        snapshot
            .rate_policy(iam_domain::RatePolicyId::from_uuid(nil()))
            .is_none()
    );
}

#[test]
fn a_counting_view_counts_every_load_and_can_be_empty() {
    let serving = CountingPolicyView::serving(GatewaySnapshot::at(version(1)));
    let empty = CountingPolicyView::empty();

    assert_eq!(serving.loads(), 0);
    assert_eq!(serving.snapshot_handles(), 1);
    let held = serving.current();
    assert!(held.is_some());
    assert_eq!(serving.snapshot_handles(), 2);
    drop(held);
    assert!(serving.current().is_some());
    assert_eq!(serving.loads(), 2);
    assert_eq!(serving.snapshot_handles(), 1);
    assert_eq!(CountingPolicyView::empty().snapshot_handles(), 0);
    assert!(empty.current().is_none());
    assert_eq!(empty.loads(), 1);
}
