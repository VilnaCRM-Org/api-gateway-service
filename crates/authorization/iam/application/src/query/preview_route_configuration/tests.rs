use std::sync::Arc;

use iam_domain::{
    EntityVersion, HttpMethod, RouteChangeClass, RouteDraft, RouteParts, RouteSetVersion,
};
use shared_domain::{Query as _, QueryHandler as _};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::route::route_draft;

use super::{PreviewRouteConfigurationQuery, PreviewRouteConfigurationQueryHandler};
use crate::error::IamError;
use crate::route_fixtures::{
    HOST, RouteWorld, Stores, actor, at, numbered_id, route_at, route_world, upstream_id,
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
