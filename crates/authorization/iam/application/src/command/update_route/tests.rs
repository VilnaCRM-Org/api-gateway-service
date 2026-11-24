use std::sync::Arc;

use iam_domain::{
    AuditSummary, ChangeStatement, CorsDraft, EnforcementMode, EntityVersion, GatewayPrecondition,
    GatewayStatement, GuardCheck, HttpMethod, IamChange, RouteConflict, ServiceName,
};
use shared_domain::{Command as _, CommandHandler as _};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::unit_of_work::FakeIamUnitOfWork;

use super::{CorsChange, RoutePatch, UpdateRouteCommand, UpdateRouteCommandHandler};
use crate::error::IamError;
use crate::route_fixtures::{
    FakeRouteTableCompiler, RouteWorld, Stores, actor, at, change_id, numbered_id, policy_holding,
    route, route_at, route_id, route_world, upstream_id,
};
use crate::upstream_fixtures::upstream_named;

fn handler(world: &RouteWorld) -> UpdateRouteCommandHandler {
    UpdateRouteCommandHandler::new(
        world.ports.clone(),
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    )
}

fn stored() -> Stores {
    Stores {
        routes: vec![route(3)],
        ..Stores::default()
    }
}

fn command(version: i64, patch: RoutePatch) -> UpdateRouteCommand {
    UpdateRouteCommand {
        change_id: change_id(),
        route_id: route_id(),
        actor: actor(),
        expected: EntityVersion::new(version).unwrap(),
        patch,
        idempotency: None,
    }
}

fn only(committed: &[IamChange]) -> &IamChange {
    let [change] = committed else {
        panic!("one change expected: {committed:?}");
    };
    change
}

fn updated_route(change: &IamChange) -> iam_domain::RouteParts {
    let [
        ChangeStatement::ExpectGateway(targets),
        ChangeStatement::ExpectGateway(table),
        ChangeStatement::SaveGateway(statement),
    ] = change.parts().statements.as_slice()
    else {
        panic!("two preconditions and one gateway statement expected");
    };
    assert!(matches!(
        targets.as_ref(),
        GatewayPrecondition::RouteTargets { .. }
    ));
    assert!(matches!(table.as_ref(), GatewayPrecondition::RouteTable(_)));
    let GatewayStatement::Route(statement) = statement.as_ref() else {
        panic!("a route statement expected");
    };
    assert_eq!(statement.expected(), Some(EntityVersion::new(3).unwrap()));
    statement.route().clone()
}

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(UpdateRouteCommand::NAME, "UpdateRouteCommand");
}

#[tokio::test]
async fn a_patch_changes_only_the_members_it_names() {
    let world = route_world(stored());
    let patch = RoutePatch {
        methods: Some(vec![HttpMethod::Get, HttpMethod::Patch]),
        request_timeout_ms: Some(5_000),
        streaming: Some(true),
        ..RoutePatch::default()
    };

    handler(&world).handle(command(3, patch)).await.unwrap();

    let committed = world.unit_of_work.committed();
    let change = only(&committed);
    let after = updated_route(change);
    assert_eq!(after.version, EntityVersion::new(4).unwrap());
    assert_eq!(after.fields.methods(), [HttpMethod::Get, HttpMethod::Patch]);
    assert_eq!(after.fields.timeouts().request_ms(), 5_000);
    assert_eq!(after.fields.timeouts().idle_ms(), 60_000);
    assert!(after.fields.flags().streaming());
    assert!(!after.fields.flags().anonymous());
    assert_eq!(after.fields.path_pattern().as_str(), "/api/orders/{id}");
    let types: Vec<&str> = change
        .parts()
        .events
        .iter()
        .map(|event| event.parts().event_type.as_str())
        .collect();
    assert_eq!(types, ["iam.route.updated"]);
    assert_eq!(
        change.guard(),
        Some(&GuardCheck::Route {
            services: vec![ServiceName::new("core").unwrap()],
            anonymous_key: false,
        })
    );
}

#[tokio::test]
async fn changing_a_flag_names_the_old_and_the_new_value_in_the_audit_record_and_asks_for_the_key()
{
    let world = route_world(stored());
    let patch = RoutePatch {
        anonymous: Some(true),
        enforcement: Some(EnforcementMode::Audit),
        ..RoutePatch::default()
    };

    handler(&world).handle(command(3, patch)).await.unwrap();

    let committed = world.unit_of_work.committed();
    let change = only(&committed);
    let audit = change.parts().audit.parts();
    assert_eq!(audit.action.as_str(), "route.update");
    assert_eq!(
        audit.before.as_ref().map(AuditSummary::as_str),
        Some("service=core anonymous=false enforcement=enforce version=3")
    );
    assert_eq!(
        audit.after.as_ref().map(AuditSummary::as_str),
        Some("service=core anonymous=true enforcement=audit version=4")
    );
    assert_eq!(
        change.guard(),
        Some(&GuardCheck::Route {
            services: vec![ServiceName::new("core").unwrap()],
            anonymous_key: true,
        })
    );
}

fn cors() -> CorsDraft {
    CorsDraft {
        origins: vec!["https://app.example.test".to_owned()],
        methods: vec![HttpMethod::Get],
        headers: Vec::new(),
        allow_credentials: false,
        max_age_seconds: 60,
    }
}

async fn cors_after(patch: RoutePatch) -> Option<iam_domain::CorsPolicy> {
    let mut with_cors = route(3);
    let mut draft = test_support::route::route_draft(
        "app.example.test",
        "/api/orders/{id}",
        &[HttpMethod::Get],
        "core",
        upstream_id(),
    );
    draft.cors = Some(cors());
    with_cors.fields = iam_domain::RouteFields::new(&draft).unwrap();
    let world = route_world(Stores {
        routes: vec![with_cors],
        ..Stores::default()
    });

    handler(&world).handle(command(3, patch)).await.unwrap();

    let committed = world.unit_of_work.committed();
    updated_route(&committed[0]).fields.cors().cloned()
}

#[tokio::test]
async fn the_cors_policy_is_kept_when_the_patch_names_none() {
    let kept = cors_after(RoutePatch {
        graphql: Some(true),
        ..RoutePatch::default()
    })
    .await;

    assert_eq!(kept.unwrap().origins(), ["https://app.example.test"]);
}

#[tokio::test]
async fn the_cors_policy_is_removed_or_replaced_when_the_patch_says_so() {
    let removed = cors_after(RoutePatch {
        cors: CorsChange::Remove,
        ..RoutePatch::default()
    })
    .await;
    let mut other = cors();
    other.origins = vec!["https://other.example.test".to_owned()];
    let replaced = cors_after(RoutePatch {
        cors: CorsChange::Set(other),
        ..RoutePatch::default()
    })
    .await;

    assert_eq!(removed, None);
    assert_eq!(replaced.unwrap().origins(), ["https://other.example.test"]);
}

#[tokio::test]
async fn a_stale_or_unknown_version_commits_nothing() {
    let world = route_world(stored());

    let stale = handler(&world)
        .handle(command(2, RoutePatch::default()))
        .await
        .unwrap_err();
    let unknown = handler(&world)
        .handle(UpdateRouteCommand {
            route_id: numbered_id(9),
            ..command(3, RoutePatch::default())
        })
        .await
        .unwrap_err();

    assert!(matches!(stale, IamError::PreconditionFailed));
    assert!(matches!(unknown, IamError::NotFound));
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn invalid_fields_are_reported_and_commit_nothing() {
    let world = route_world(stored());
    let patch = RoutePatch {
        path_pattern: Some("orders".to_owned()),
        ..RoutePatch::default()
    };

    let error = handler(&world).handle(command(3, patch)).await.unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("violations expected: {error:?}");
    };
    assert_eq!(violations[0].property_path, "pathPattern");
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn a_system_route_and_a_route_of_the_iam_service_are_refused_and_audited() {
    let mut system = route(3);
    system.system = true;
    let world = route_world(Stores {
        routes: vec![system],
        policy: Some(policy_holding(&["iam:route:core"])),
        ..Stores::default()
    });

    let error = handler(&world)
        .handle(command(3, RoutePatch::default()))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::SystemEntry));
    let offered = world.attempts.offered();
    assert_eq!(offered[0].action.as_str(), "route.update");
    assert_eq!(offered[0].reason.as_str(), "system_entry");
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn moving_a_route_to_another_service_asks_for_both_route_keys() {
    let world = route_world(Stores {
        routes: vec![route(3)],
        upstreams: vec![upstream_named(upstream_id(), "payment", "payment", 1)],
        ..Stores::default()
    });
    let patch = RoutePatch {
        service: Some("payment".to_owned()),
        ..RoutePatch::default()
    };

    handler(&world).handle(command(3, patch)).await.unwrap();

    let committed = world.unit_of_work.committed();
    assert_eq!(
        only(&committed).guard(),
        Some(&GuardCheck::Route {
            services: vec![
                ServiceName::new("core").unwrap(),
                ServiceName::new("payment").unwrap()
            ],
            anonymous_key: false,
        })
    );
}

#[tokio::test]
async fn a_service_that_differs_from_the_catalogue_service_of_the_upstream_is_a_violation() {
    let world = route_world(stored());
    let patch = RoutePatch {
        service: Some("payment".to_owned()),
        ..RoutePatch::default()
    };

    let error = handler(&world).handle(command(3, patch)).await.unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("violations expected: {error:?}");
    };
    assert_eq!(violations[0].property_path, "service");
}

#[tokio::test]
async fn an_update_that_conflicts_with_another_route_is_refused() {
    let other = route_at(numbered_id(5), "/api/orders", &[HttpMethod::Get], 1);
    let world = route_world(Stores {
        routes: vec![route(3), other],
        ..Stores::default()
    });
    let patch = RoutePatch {
        path_pattern: Some("/api/orders".to_owned()),
        ..RoutePatch::default()
    };

    let error = handler(&world).handle(command(3, patch)).await.unwrap_err();

    assert!(matches!(error, IamError::RouteTableConflict { .. }));
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn a_route_does_not_conflict_with_its_own_stored_state() {
    let world = route_world(stored());

    handler(&world)
        .handle(command(3, RoutePatch::default()))
        .await
        .unwrap();

    assert_eq!(world.unit_of_work.committed().len(), 1);
}

#[tokio::test]
async fn a_candidate_table_that_the_gateway_could_not_build_is_refused() {
    let world = route_world(Stores {
        compiler: FakeRouteTableCompiler::refusing(RouteConflict::SamePattern {
            first: route_id(),
            second: numbered_id(5),
        }),
        ..stored()
    });

    let error = handler(&world)
        .handle(command(3, RoutePatch::default()))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::RouteTableConflict { .. }));
}

#[tokio::test]
async fn a_failing_unit_of_work_is_the_error_of_the_command() {
    let world = route_world(Stores {
        unit_of_work: FakeIamUnitOfWork::failing(),
        ..stored()
    });

    let error = handler(&world)
        .handle(command(3, RoutePatch::default()))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}

#[tokio::test]
async fn a_route_on_the_host_of_the_seeded_iam_routes_cannot_be_changed() {
    let mut system = route_at(numbered_id(9), "/api/{rest:*}", &[HttpMethod::Post], 1);
    system.system = true;
    let world = route_world(Stores {
        routes: vec![route(3), system],
        policy: Some(policy_holding(&["iam:route:core"])),
        ..Stores::default()
    });

    let error = handler(&world)
        .handle(command(3, RoutePatch::default()))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::SystemEntry), "{error:?}");
    let offered = world.attempts.offered();
    assert_eq!(offered[0].action.as_str(), "route.update");
    assert_eq!(offered[0].reason.as_str(), "system_entry");
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn a_route_cannot_be_moved_onto_the_host_of_the_seeded_iam_routes() {
    let mut system = route_at(numbered_id(9), "/api/{rest:*}", &[HttpMethod::Post], 1);
    system.system = true;
    system.fields = iam_domain::RouteFields::new(&test_support::route::route_draft(
        "iam.example.test",
        "/api/{rest:*}",
        &[HttpMethod::Post],
        "iam",
        upstream_id(),
    ))
    .unwrap();
    let world = route_world(Stores {
        routes: vec![route(3), system],
        ..Stores::default()
    });
    let patch = RoutePatch {
        host: Some("iam.example.test".to_owned()),
        ..RoutePatch::default()
    };

    let error = handler(&world).handle(command(3, patch)).await.unwrap_err();

    assert!(matches!(error, IamError::SystemEntry), "{error:?}");
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}
