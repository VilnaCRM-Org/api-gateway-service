use std::sync::Arc;

use iam_domain::{
    ActorRef, EntityVersion, HttpMethod, RouteChangeClass, RouteDraft, RouteFlag, RouteFlags,
    RouteParts, RouteSetVersion, ServiceName, SystemComponent,
};
use shared_domain::{Query as _, QueryHandler as _};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::route::route_draft;

use super::{PreviewRouteConfigurationQuery, PreviewRouteConfigurationQueryHandler};
use crate::error::IamError;
use crate::route_fixtures::{
    HOST, RouteWorld, Stores, actor, at, numbered_id, policy_holding, route_at, route_world,
    upstream_id,
};

const GET: &[HttpMethod] = &[HttpMethod::Get];

fn handler(world: &RouteWorld, max_routes: usize) -> PreviewRouteConfigurationQueryHandler {
    PreviewRouteConfigurationQueryHandler::new(
        world.ports.clone(),
        max_routes,
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    )
}

fn draft(path: &str) -> RouteDraft {
    route_draft(HOST, path, GET, "core", upstream_id())
}

fn stored() -> Vec<RouteParts> {
    vec![
        route_at(numbered_id(1), "/a", GET, 3),
        route_at(numbered_id(2), "/b", GET, 3),
    ]
}

fn query(routes: Vec<RouteDraft>, expected: EntityVersion) -> PreviewRouteConfigurationQuery {
    PreviewRouteConfigurationQuery {
        host: HOST.to_owned(),
        routes,
        expected,
        actor: actor(),
    }
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(
        PreviewRouteConfigurationQuery::NAME,
        "PreviewRouteConfigurationQuery"
    );
}

#[tokio::test]
async fn a_dry_run_lists_the_diff_and_writes_nothing() {
    let routes = stored();
    let world = route_world(Stores {
        routes: routes.clone(),
        policy: Some(policy_holding(&["iam:route:*"])),
        ..Stores::default()
    });
    let mut slower = draft("/b");
    slower.request_timeout_ms = 5_000;

    let preview = handler(&world, 1_000)
        .handle(query(
            vec![slower, draft("/c")],
            RouteSetVersion::of(&routes),
        ))
        .await
        .unwrap();

    assert_eq!(preview.host.to_string(), HOST);
    assert_eq!(preview.version, RouteSetVersion::of(&routes));
    assert_eq!(preview.route_count, 2);
    assert_eq!(preview.diff.added().len(), 1);
    assert_eq!(preview.diff.changed().len(), 1);
    assert_eq!(preview.diff.removed().len(), 1);
    assert_eq!(preview.diff.class(), RouteChangeClass::Revocation);
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn a_dry_run_is_refused_exactly_when_the_application_would_be() {
    let routes = stored();
    let world = route_world(Stores {
        routes: routes.clone(),
        policy: Some(policy_holding(&["iam:route:*"])),
        ..Stores::default()
    });

    let stale = handler(&world, 1_000)
        .handle(query(vec![draft("/c")], EntityVersion::new(9).unwrap()))
        .await
        .unwrap_err();
    let too_many = handler(&world, 1)
        .handle(query(
            vec![draft("/a"), draft("/b")],
            RouteSetVersion::of(&routes),
        ))
        .await
        .unwrap_err();
    let conflicting = handler(&world, 1_000)
        .handle(query(
            vec![draft("/users/{id}"), draft("/users/{name}")],
            RouteSetVersion::of(&routes),
        ))
        .await
        .unwrap_err();

    assert!(matches!(stale, IamError::PreconditionFailed));
    assert!(matches!(too_many, IamError::Invalid(_)));
    assert!(matches!(conflicting, IamError::RouteTableConflict { .. }));
}

fn anonymous(path: &str) -> RouteDraft {
    let mut route = draft(path);
    route.flags = RouteFlags::default().with(RouteFlag::Anonymous, true);
    route
}

fn world_holding(grants: &[&str]) -> RouteWorld {
    route_world(Stores {
        policy: Some(policy_holding(grants)),
        ..Stores::default()
    })
}

async fn refused_reason(world: &RouteWorld, routes: Vec<RouteDraft>) -> Option<String> {
    let result = handler(world, 1_000)
        .handle(query(routes, RouteSetVersion::of(&[])))
        .await;
    match result {
        Ok(_) => None,
        Err(error) => {
            assert!(matches!(error, IamError::Forbidden), "{error:?}");
            let offered = world.attempts.offered();
            let [attempt] = offered.as_slice() else {
                panic!("one attempt expected: {offered:?}");
            };
            assert_eq!(attempt.action.as_str(), "route_configuration.apply");
            assert_eq!(world.unit_of_work.committed(), Vec::new());
            Some(attempt.reason.as_str().to_owned())
        }
    }
}

#[tokio::test]
async fn a_dry_run_without_the_route_key_of_a_service_is_forbidden_and_audited() {
    let world = world_holding(&["iam:route:other"]);

    let reason = refused_reason(&world, vec![draft("/a")]).await;

    assert_eq!(reason.as_deref(), Some("route_scope.denied"));
}

#[tokio::test]
async fn a_dry_run_with_no_policy_at_all_is_forbidden() {
    let world = route_world(Stores::default());

    let reason = refused_reason(&world, vec![draft("/a")]).await;

    assert_eq!(reason.as_deref(), Some("route_scope.denied"));
}

#[rstest::rstest]
#[case::service_key(&["iam:route:core"])]
#[case::global_key(&["iam:route:*"])]
#[tokio::test]
async fn a_dry_run_with_the_route_key_of_the_service_is_let_through(#[case] grants: &[&str]) {
    let world = world_holding(grants);

    assert_eq!(refused_reason(&world, vec![draft("/a")]).await, None);
    assert_eq!(world.attempts.offered(), Vec::new());
}

#[tokio::test]
async fn a_dry_run_of_an_anonymous_route_needs_the_anonymous_key() {
    let world = world_holding(&["iam:route:core"]);

    let reason = refused_reason(&world, vec![anonymous("/a")]).await;

    assert_eq!(reason.as_deref(), Some("anonymous_route_forbidden"));
}

#[tokio::test]
async fn a_dry_run_of_an_anonymous_route_is_let_through_for_a_holder_of_the_anonymous_key() {
    let world = world_holding(&["iam:route:core", "iam:route:anonymous"]);

    assert_eq!(refused_reason(&world, vec![anonymous("/a")]).await, None);
}

#[tokio::test]
async fn a_dry_run_of_an_iam_component_is_let_through_without_a_policy() {
    let world = route_world(Stores::default());
    let mut system = query(vec![draft("/a")], RouteSetVersion::of(&[]));
    system.actor = ActorRef::System(SystemComponent::Startup);

    let preview = handler(&world, 1_000).handle(system).await.unwrap();

    assert_eq!(preview.host.to_string(), HOST);
    assert_eq!(world.attempts.offered(), Vec::new());
}

#[tokio::test]
async fn a_dry_run_of_a_service_without_the_route_key_is_forbidden_and_audited() {
    let world = route_world(Stores::default());
    let mut service = query(vec![draft("/a")], RouteSetVersion::of(&[]));
    service.actor = ActorRef::Service(ServiceName::new("billing").unwrap());

    let error = handler(&world, 1_000).handle(service).await.unwrap_err();

    assert!(matches!(error, IamError::Forbidden), "{error:?}");
    assert_eq!(world.attempts.offered().len(), 1);
}
