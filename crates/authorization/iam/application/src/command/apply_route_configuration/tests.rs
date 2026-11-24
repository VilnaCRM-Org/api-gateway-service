use std::sync::Arc;

use iam_domain::{
    ChangeStatement, EntityVersion, EventValue, GatewayStatement, GuardCheck, HttpMethod,
    IamChange, RouteConflict, RouteDraft, RouteFlag, RouteFlags, RouteParts, RouteSetVersion,
    ServiceName,
};
use shared_domain::{Command as _, CommandHandler as _};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::route::route_draft;

use super::{ApplyRouteConfigurationCommand, ApplyRouteConfigurationCommandHandler};
use crate::error::IamError;
use crate::route_fixtures::{
    FakeRouteTableCompiler, HOST, RouteWorld, Stores, actor, at, change_id, numbered_id,
    policy_holding, route_at, route_world, upstream_id,
};
use crate::upstream_fixtures::upstream_named;

const GET: &[HttpMethod] = &[HttpMethod::Get];

fn handler(world: &RouteWorld, max_routes: usize) -> ApplyRouteConfigurationCommandHandler {
    ApplyRouteConfigurationCommandHandler::new(
        world.ports.clone(),
        max_routes,
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    )
}

fn draft(path: &str) -> RouteDraft {
    route_draft(HOST, path, GET, "core", upstream_id())
}

fn stored_pair() -> Vec<RouteParts> {
    vec![
        route_at(numbered_id(1), "/a", GET, 3),
        route_at(numbered_id(2), "/b", GET, 3),
    ]
}

fn world_with(routes: Vec<RouteParts>) -> RouteWorld {
    route_world(Stores {
        routes,
        ..Stores::default()
    })
}

fn command(routes: Vec<RouteDraft>, expected: EntityVersion) -> ApplyRouteConfigurationCommand {
    ApplyRouteConfigurationCommand {
        change_id: change_id(),
        host: HOST.to_owned(),
        routes,
        actor: actor(),
        expected,
    }
}

fn current(routes: &[RouteParts]) -> EntityVersion {
    RouteSetVersion::of(routes)
}

fn only(committed: &[IamChange]) -> &IamChange {
    let [change] = committed else {
        panic!("one change expected: {committed:?}");
    };
    change
}

fn event_types(change: &IamChange) -> Vec<&str> {
    change
        .parts()
        .events
        .iter()
        .map(|event| event.parts().event_type.as_str())
        .collect()
}

fn written(change: &IamChange) -> Vec<(Option<EntityVersion>, RouteParts)> {
    change
        .parts()
        .statements
        .iter()
        .map(|statement| {
            let ChangeStatement::SaveGateway(statement) = statement else {
                panic!("a gateway statement expected");
            };
            let GatewayStatement::Route(statement) = statement.as_ref() else {
                panic!("a route statement expected");
            };
            (statement.expected(), statement.route().clone())
        })
        .collect()
}

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(
        ApplyRouteConfigurationCommand::NAME,
        "ApplyRouteConfigurationCommand"
    );
}

#[tokio::test]
async fn a_set_deletes_updates_and_creates_routes_in_one_change() {
    let stored = stored_pair();
    let world = world_with(stored.clone());
    let mut slower = draft("/b");
    slower.request_timeout_ms = 5_000;

    handler(&world, 1_000)
        .handle(command(vec![slower, draft("/c")], current(&stored)))
        .await
        .unwrap();

    let committed = world.unit_of_work.committed();
    let change = only(&committed);
    let writes = written(change);
    let [
        (deleted_expected, deleted),
        (updated_expected, updated),
        (created_expected, created),
    ] = writes.as_slice()
    else {
        panic!("three statements expected: {writes:?}");
    };
    assert_eq!(*deleted_expected, Some(EntityVersion::new(3).unwrap()));
    assert!(deleted.deleted_at.is_some());
    assert_eq!(deleted.fields.path_pattern().as_str(), "/a");
    assert_eq!(*updated_expected, Some(EntityVersion::new(3).unwrap()));
    assert_eq!(updated.version, EntityVersion::new(4).unwrap());
    assert_eq!(updated.fields.timeouts().request_ms(), 5_000);
    assert_eq!(*created_expected, None);
    assert_eq!(created.version, EntityVersion::INITIAL);
    assert_eq!(created.fields.path_pattern().as_str(), "/c");
    assert_eq!(
        event_types(change),
        [
            "iam.route.deleted",
            "iam.route.updated",
            "iam.route.created",
            "iam.route_configuration.applied"
        ]
    );
    assert!(change.is_revocation_class());
    assert_eq!(
        change.parts().entity_version,
        RouteSetVersion::of(&[updated.clone(), created.clone()])
    );
}

#[tokio::test]
async fn the_applied_event_names_the_host_and_the_routes_it_changed() {
    let stored = stored_pair();
    let world = world_with(stored.clone());

    handler(&world, 1_000)
        .handle(command(vec![draft("/b"), draft("/c")], current(&stored)))
        .await
        .unwrap();

    let committed = world.unit_of_work.committed();
    let change = only(&committed);
    let applied = change.parts().events.last().unwrap().parts();
    let field = |name: &str| {
        applied
            .data
            .fields()
            .iter()
            .find(|(field, _value)| field.as_str() == name)
            .map(|(_field, value)| value.clone())
            .unwrap()
    };
    assert_eq!(field("host"), EventValue::Text(HOST.to_owned()));
    assert_eq!(field("routeCount"), EventValue::Integer(2));
    assert_eq!(field("createdCount"), EventValue::Integer(1));
    assert_eq!(field("updatedCount"), EventValue::Integer(0));
    assert_eq!(field("deletedCount"), EventValue::Integer(1));
}

#[tokio::test]
async fn the_audit_record_names_the_host_and_the_counts_before_and_after() {
    let stored = stored_pair();
    let world = world_with(stored.clone());

    handler(&world, 1_000)
        .handle(command(vec![draft("/b"), draft("/c")], current(&stored)))
        .await
        .unwrap();

    let committed = world.unit_of_work.committed();
    let audit = only(&committed).parts().audit.parts();
    assert_eq!(audit.action.as_str(), "route_configuration.apply");
    assert_eq!(audit.target.target_type(), "route_configuration");
    assert_eq!(audit.target.target_id(), HOST);
    let before = audit.before.as_ref().unwrap().as_str();
    assert!(before.starts_with("routes=2 version="), "{before}");
    let after = audit.after.as_ref().unwrap().as_str();
    assert!(after.starts_with("routes=2 version="), "{after}");
    assert!(after.ends_with("created=1 updated=0 deleted=1"), "{after}");
}

#[tokio::test]
async fn a_set_that_only_adds_routes_is_not_revocation_class() {
    let stored = stored_pair();
    let world = world_with(stored.clone());

    handler(&world, 1_000)
        .handle(command(
            vec![draft("/a"), draft("/b"), draft("/c")],
            current(&stored),
        ))
        .await
        .unwrap();

    let committed = world.unit_of_work.committed();
    let change = only(&committed);
    assert!(!change.is_revocation_class());
    assert!(change.affects_decisions());
    assert_eq!(
        change.guard(),
        Some(&GuardCheck::Route {
            services: vec![ServiceName::new("core").unwrap()],
            anonymous_key: false,
        })
    );
}

#[tokio::test]
async fn a_set_that_changes_nothing_commits_nothing() {
    let stored = stored_pair();
    let world = world_with(stored.clone());

    handler(&world, 1_000)
        .handle(command(vec![draft("/a"), draft("/b")], current(&stored)))
        .await
        .unwrap();

    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn an_anonymous_route_asks_the_unit_of_work_for_the_anonymous_key() {
    let world = world_with(Vec::new());
    let mut open = draft("/open");
    open.flags = RouteFlags::default().with(RouteFlag::Anonymous, true);

    handler(&world, 1_000)
        .handle(command(vec![open], current(&[])))
        .await
        .unwrap();

    let committed = world.unit_of_work.committed();
    assert_eq!(
        only(&committed).guard(),
        Some(&GuardCheck::Route {
            services: vec![ServiceName::new("core").unwrap()],
            anonymous_key: true,
        })
    );
}

#[tokio::test]
async fn changing_anonymous_of_a_stored_route_asks_for_the_anonymous_key() {
    let stored = vec![route_at(numbered_id(1), "/a", GET, 3)];
    let world = world_with(stored.clone());
    let mut open = draft("/a");
    open.flags = RouteFlags::default().with(RouteFlag::Anonymous, true);

    handler(&world, 1_000)
        .handle(command(vec![open], current(&stored)))
        .await
        .unwrap();

    let committed = world.unit_of_work.committed();
    let change = only(&committed);
    assert_eq!(
        change.guard(),
        Some(&GuardCheck::Route {
            services: vec![ServiceName::new("core").unwrap()],
            anonymous_key: true,
        })
    );
    assert!(!change.is_revocation_class());
}

#[tokio::test]
async fn a_stale_version_is_refused_and_nothing_is_committed() {
    let stored = stored_pair();
    let world = world_with(stored);

    let error = handler(&world, 1_000)
        .handle(command(vec![draft("/c")], EntityVersion::new(7).unwrap()))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::PreconditionFailed));
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn a_set_above_the_limit_is_refused_and_a_set_at_the_limit_is_applied() {
    let world = world_with(Vec::new());
    let routes = vec![draft("/a"), draft("/b")];

    let error = handler(&world, 1)
        .handle(command(routes.clone(), current(&[])))
        .await
        .unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("a validation failure expected");
    };
    assert_eq!(violations[0].property_path, "routes");
    assert_eq!(violations[0].code, "max_items");
    assert_eq!(world.unit_of_work.committed(), Vec::new());

    handler(&world, 2)
        .handle(command(routes, current(&[])))
        .await
        .unwrap();
    assert_eq!(world.unit_of_work.committed().len(), 1);
}

#[tokio::test]
async fn an_invalid_route_names_its_position_in_the_set() {
    let world = world_with(Vec::new());
    let mut broken = draft("/b");
    broken.methods = Vec::new();

    let error = handler(&world, 1_000)
        .handle(command(vec![draft("/a"), broken], current(&[])))
        .await
        .unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("a validation failure expected");
    };
    assert_eq!(violations[0].property_path, "routes[1].methods");
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn an_invalid_host_is_a_violation_of_host() {
    let world = world_with(Vec::new());
    let mut command = command(Vec::new(), current(&[]));
    command.host = "Not A Host".to_owned();

    let error = handler(&world, 1_000).handle(command).await.unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("a validation failure expected");
    };
    assert_eq!(violations[0].property_path, "host");
}

#[tokio::test]
async fn routes_that_conflict_reject_the_whole_set() {
    let world = world_with(Vec::new());

    let error = handler(&world, 1_000)
        .handle(command(
            vec![draft("/users/{id}"), draft("/users/{name}"), draft("/x")],
            current(&[]),
        ))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::RouteTableConflict { .. }));
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn a_route_table_that_the_gateway_cannot_build_rejects_the_set() {
    let world = route_world(Stores {
        compiler: FakeRouteTableCompiler::refusing(RouteConflict::SamePattern {
            first: numbered_id(1),
            second: numbered_id(2),
        }),
        ..Stores::default()
    });

    let error = handler(&world, 1_000)
        .handle(command(vec![draft("/a")], current(&[])))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::RouteTableConflict { .. }));
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn deleting_a_system_route_is_a_system_entry_and_audited() {
    let mut system = route_at(numbered_id(1), "/a", GET, 3);
    system.system = true;
    let stored = vec![system];
    let world = world_with(stored.clone());

    let error = handler(&world, 1_000)
        .handle(command(Vec::new(), current(&stored)))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::SystemEntry));
    let offered = world.attempts.offered();
    let [attempt] = offered.as_slice() else {
        panic!("one attempt expected: {offered:?}");
    };
    assert_eq!(attempt.action.as_str(), "route_configuration.apply");
    assert_eq!(attempt.reason.as_str(), "system_entry");
    assert_eq!(attempt.target.target_id(), HOST);
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn changing_a_system_route_is_a_system_entry() {
    let mut system = route_at(numbered_id(1), "/a", GET, 3);
    system.system = true;
    let stored = vec![system];
    let world = world_with(stored.clone());
    let mut slower = draft("/a");
    slower.request_timeout_ms = 5_000;

    let error = handler(&world, 1_000)
        .handle(command(vec![slower], current(&stored)))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::SystemEntry));
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn keeping_a_system_route_as_it_is_is_allowed() {
    let mut system = route_at(numbered_id(1), "/a", GET, 3);
    system.system = true;
    let stored = vec![system];
    let world = world_with(stored.clone());

    handler(&world, 1_000)
        .handle(command(vec![draft("/a"), draft("/b")], current(&stored)))
        .await
        .unwrap();

    assert_eq!(world.unit_of_work.committed().len(), 1);
}

#[tokio::test]
async fn a_route_of_the_iam_service_is_forbidden_without_the_iam_route_key() {
    let world = route_world(Stores {
        upstreams: vec![upstream_named(upstream_id(), "iam-control", "iam", 1)],
        policy: Some(policy_holding(&["iam:route:core"])),
        ..Stores::default()
    });
    let iam = route_draft(HOST, "/a", GET, "iam", upstream_id());

    let error = handler(&world, 1_000)
        .handle(command(vec![iam], current(&[])))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Forbidden));
    assert_eq!(
        world.attempts.offered()[0].reason.as_str(),
        "route_scope.denied"
    );
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn a_route_of_the_iam_service_is_a_system_entry_for_a_holder_of_the_global_route_key() {
    let world = route_world(Stores {
        policy: Some(policy_holding(&["iam:route:*"])),
        ..Stores::default()
    });
    let iam = route_draft(HOST, "/a", GET, "iam", upstream_id());

    let error = handler(&world, 1_000)
        .handle(command(vec![iam], current(&[])))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::SystemEntry));
}

#[tokio::test]
async fn a_route_of_an_unknown_upstream_is_a_violation_of_upstream_id() {
    let world = route_world(Stores {
        upstreams: Vec::new(),
        ..Stores::default()
    });

    let error = handler(&world, 1_000)
        .handle(command(vec![draft("/a")], current(&[])))
        .await
        .unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("a validation failure expected");
    };
    assert_eq!(violations[0].property_path, "upstreamId");
}

#[tokio::test]
async fn a_route_whose_service_differs_from_its_upstream_is_a_violation_of_service() {
    let world = world_with(Vec::new());
    let other = route_draft(HOST, "/a", GET, "billing", upstream_id());

    let error = handler(&world, 1_000)
        .handle(command(vec![other], current(&[])))
        .await
        .unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("a validation failure expected");
    };
    assert_eq!(violations[0].property_path, "service");
}

#[tokio::test]
async fn services_of_removed_and_changed_routes_are_all_guarded_once() {
    let mut billing = route_at(numbered_id(2), "/b", GET, 3);
    billing.fields =
        iam_domain::RouteFields::new(&route_draft(HOST, "/b", GET, "billing", upstream_id()))
            .unwrap();
    let stored = vec![route_at(numbered_id(1), "/a", GET, 3), billing];
    let world = world_with(stored.clone());

    handler(&world, 1_000)
        .handle(command(vec![draft("/a"), draft("/c")], current(&stored)))
        .await
        .unwrap();

    let committed = world.unit_of_work.committed();
    assert_eq!(
        only(&committed).guard(),
        Some(&GuardCheck::Route {
            services: vec![
                ServiceName::new("billing").unwrap(),
                ServiceName::new("core").unwrap()
            ],
            anonymous_key: false,
        })
    );
}
