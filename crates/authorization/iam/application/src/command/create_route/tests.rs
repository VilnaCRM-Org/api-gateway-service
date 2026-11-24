use std::sync::Arc;

use iam_domain::{
    AuditOutcome, AuditSummary, ChangeStatement, CorsDraft, DecisionEffect, EnforcementMode,
    EntityVersion, GatewayPrecondition, GatewayStatement, GuardCheck, HttpMethod, RatePolicyId,
    RouteConflict, RouteDraft, RouteFlag, RouteFlags, ServiceName,
};
use shared_domain::{Command as _, CommandHandler as _};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::route::route_draft;
use test_support::unit_of_work::FakeIamUnitOfWork;

use super::{CreateRouteCommand, CreateRouteCommandHandler};
use crate::error::IamError;
use crate::rate_policy_fixtures::{POLICY, rate_policy};
use crate::route_fixtures::{
    FakeRouteTableCompiler, RouteWorld, Stores, actor, at, change_id, numbered_id, policy_holding,
    route_at, route_id, route_world, upstream_id,
};
use crate::upstream_fixtures::upstream_named;

fn handler(world: &RouteWorld) -> CreateRouteCommandHandler {
    CreateRouteCommandHandler::new(
        world.ports.clone(),
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    )
}

fn draft_of(service: &str) -> RouteDraft {
    route_draft(
        "app.example.test",
        "/api/orders/{id}",
        &[HttpMethod::Get],
        service,
        upstream_id(),
    )
}

fn command(draft: RouteDraft) -> CreateRouteCommand {
    CreateRouteCommand {
        change_id: change_id(),
        route_id: route_id(),
        actor: actor(),
        draft,
        idempotency: None,
    }
}

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(CreateRouteCommand::NAME, "CreateRouteCommand");
}

#[tokio::test]
async fn a_valid_route_is_committed_as_one_insert_with_its_event_and_audit_record() {
    let world = route_world(Stores::default());

    handler(&world)
        .handle(command(draft_of("core")))
        .await
        .unwrap();

    let committed = world.unit_of_work.committed();
    let [change] = committed.as_slice() else {
        panic!("one change expected: {committed:?}");
    };
    let parts = change.parts();
    assert_eq!(parts.change_id, change_id());
    assert_eq!(parts.effect, DecisionEffect::Affected);
    assert_eq!(parts.entity_version, EntityVersion::INITIAL);
    let [
        ChangeStatement::ExpectGateway(targets),
        ChangeStatement::ExpectGateway(table),
        ChangeStatement::SaveGateway(statement),
    ] = parts.statements.as_slice()
    else {
        panic!(
            "two preconditions and one gateway statement expected: {:?}",
            parts.statements
        );
    };
    let GatewayPrecondition::RouteTargets {
        upstream_id: target,
        service,
        rate_policies,
    } = targets.as_ref()
    else {
        panic!("the targets of the route expected: {targets:?}");
    };
    assert_eq!(*target, upstream_id());
    assert_eq!(service.as_str(), "core");
    assert_eq!(rate_policies.len(), 0);
    assert!(
        matches!(table.as_ref(), GatewayPrecondition::RouteTable(route) if route.id == route_id())
    );
    let GatewayStatement::Route(statement) = statement.as_ref() else {
        panic!("a route statement expected: {statement:?}");
    };
    assert_eq!(statement.expected(), None);
    assert_eq!(statement.route().id, route_id());
    assert_eq!(
        statement.route().fields.path_pattern().as_str(),
        "/api/orders/{id}"
    );
    assert!(!statement.route().system);
    let types: Vec<&str> = parts
        .events
        .iter()
        .map(|event| event.parts().event_type.as_str())
        .collect();
    assert_eq!(types, ["iam.route.created"]);
    assert_eq!(world.attempts.offered().len(), 0);
}

#[tokio::test]
async fn the_audit_record_names_the_actor_the_route_and_the_flags() {
    let world = route_world(Stores::default());

    handler(&world)
        .handle(command(draft_of("core")))
        .await
        .unwrap();

    let committed = world.unit_of_work.committed();
    let audit = committed[0].parts().audit.parts();
    assert_eq!(audit.action.as_str(), "route.create");
    assert_eq!(audit.outcome, AuditOutcome::Committed);
    assert_eq!(audit.actor, actor());
    assert_eq!(audit.target.target_type(), "route");
    assert_eq!(audit.target.target_id(), route_id().to_string());
    assert_eq!(audit.before, None);
    assert_eq!(
        audit.after.as_ref().map(AuditSummary::as_str),
        Some("service=core anonymous=false enforcement=enforce version=1")
    );
}

#[tokio::test]
async fn a_protected_route_asks_for_the_route_scope_check_alone() {
    let world = route_world(Stores::default());

    handler(&world)
        .handle(command(draft_of("core")))
        .await
        .unwrap();

    assert_eq!(
        world.unit_of_work.committed()[0].guard(),
        Some(&GuardCheck::Route {
            services: vec![ServiceName::new("core").unwrap()],
            anonymous_key: false,
        })
    );
}

#[tokio::test]
async fn an_anonymous_or_audit_only_route_asks_for_the_anonymous_key() {
    let mut anonymous = draft_of("core");
    anonymous.flags = RouteFlags::default().with(RouteFlag::Anonymous, true);
    let mut audit = draft_of("core");
    audit.enforcement = EnforcementMode::Audit;
    let asked = GuardCheck::Route {
        services: vec![ServiceName::new("core").unwrap()],
        anonymous_key: true,
    };

    for draft in [anonymous, audit] {
        let world = route_world(Stores::default());

        handler(&world).handle(command(draft)).await.unwrap();

        assert_eq!(world.unit_of_work.committed()[0].guard(), Some(&asked));
    }
}

#[tokio::test]
async fn a_cors_policy_is_stored_with_the_route() {
    let world = route_world(Stores::default());
    let mut draft = draft_of("core");
    draft.cors = Some(CorsDraft {
        origins: vec!["https://app.example.test".to_owned()],
        methods: vec![HttpMethod::Get],
        headers: vec!["content-type".to_owned()],
        allow_credentials: true,
        max_age_seconds: 600,
    });

    handler(&world).handle(command(draft)).await.unwrap();

    let committed = world.unit_of_work.committed();
    let [_, _, ChangeStatement::SaveGateway(statement)] =
        committed[0].parts().statements.as_slice()
    else {
        panic!("two preconditions and one gateway statement expected");
    };
    let GatewayStatement::Route(statement) = statement.as_ref() else {
        panic!("a route statement expected");
    };
    let cors = statement.route().fields.cors().unwrap();
    assert_eq!(cors.origins(), ["https://app.example.test"]);
    assert_eq!(cors.max_age_seconds(), 600);
}

#[tokio::test]
async fn invalid_fields_are_reported_together_and_commit_nothing() {
    let world = route_world(Stores::default());
    let mut invalid = draft_of("core");
    invalid.host = "Not A Host".to_owned();
    invalid.body_limit = 0;

    let error = handler(&world).handle(command(invalid)).await.unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("violations expected: {error:?}");
    };
    let paths: Vec<&str> = violations
        .iter()
        .map(|violation| violation.property_path.as_str())
        .collect();
    assert_eq!(paths, ["host", "bodyLimitBytes"]);
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn an_unknown_upstream_is_a_violation_of_the_upstream_id() {
    let world = route_world(Stores {
        upstreams: Vec::new(),
        ..Stores::default()
    });

    let error = handler(&world)
        .handle(command(draft_of("core")))
        .await
        .unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("violations expected: {error:?}");
    };
    assert_eq!(violations[0].property_path, "upstreamId");
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn a_service_other_than_the_catalogue_service_of_the_upstream_is_a_violation() {
    let world = route_world(Stores {
        upstreams: vec![upstream_named(upstream_id(), "payment", "payment", 1)],
        ..Stores::default()
    });

    let error = handler(&world)
        .handle(command(draft_of("core")))
        .await
        .unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("violations expected: {error:?}");
    };
    assert_eq!(violations[0].property_path, "service");
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn an_unknown_rate_policy_is_a_violation_and_a_stored_one_is_accepted() {
    let known = rate_policy(1);
    let world = route_world(Stores {
        rate_policies: vec![known.clone()],
        ..Stores::default()
    });
    let mut stored = draft_of("core");
    stored.rate_policies = vec![known.id];
    let mut unknown = draft_of("core");
    unknown.rate_policies = vec![RatePolicyId::from_uuid(numbered_id(77).as_uuid())];

    handler(&world).handle(command(stored)).await.unwrap();
    let error = handler(&world).handle(command(unknown)).await.unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("violations expected: {error:?}");
    };
    assert_eq!(violations[0].property_path, "ratePolicyIds");
    assert_eq!(world.unit_of_work.committed().len(), 1);
    assert_eq!(POLICY, known.id.to_string());
}

#[tokio::test]
async fn a_route_that_overlaps_a_stored_route_is_a_route_table_conflict() {
    let stored = route_at(
        numbered_id(5),
        "/api/orders/{id}",
        &[HttpMethod::Get, HttpMethod::Patch],
        1,
    );
    let world = route_world(Stores {
        routes: vec![stored],
        ..Stores::default()
    });

    let error = handler(&world)
        .handle(command(draft_of("core")))
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        IamError::RouteTableConflict {
            code: "same_pattern"
        }
    ));
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn the_same_pattern_with_another_method_is_accepted() {
    let stored = route_at(numbered_id(5), "/api/orders/{id}", &[HttpMethod::Get], 1);
    let world = route_world(Stores {
        routes: vec![stored],
        ..Stores::default()
    });
    let mut other = draft_of("core");
    other.methods = vec![HttpMethod::Delete];

    handler(&world).handle(command(other)).await.unwrap();

    assert_eq!(world.unit_of_work.committed().len(), 1);
}

#[tokio::test]
async fn a_candidate_table_that_the_gateway_could_not_build_is_refused() {
    let world = route_world(Stores {
        compiler: FakeRouteTableCompiler::refusing(RouteConflict::SamePattern {
            first: route_id(),
            second: numbered_id(5),
        }),
        ..Stores::default()
    });

    let error = handler(&world)
        .handle(command(draft_of("core")))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::RouteTableConflict { .. }));
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn a_route_of_the_iam_service_is_forbidden_without_the_iam_route_key_and_audited() {
    let world = route_world(Stores {
        upstreams: vec![upstream_named(upstream_id(), "iam-control", "iam", 1)],
        policy: Some(policy_holding(&["iam:route:core"])),
        ..Stores::default()
    });

    let error = handler(&world)
        .handle(command(draft_of("iam")))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Forbidden));
    let offered = world.attempts.offered();
    let [attempt] = offered.as_slice() else {
        panic!("one attempt expected: {offered:?}");
    };
    assert_eq!(attempt.action.as_str(), "route.create");
    assert_eq!(attempt.reason.as_str(), "route_scope.denied");
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn a_route_of_the_iam_service_is_a_system_entry_for_a_holder_of_the_iam_route_key() {
    let world = route_world(Stores {
        policy: Some(policy_holding(&["iam:route:iam"])),
        ..Stores::default()
    });

    let error = handler(&world)
        .handle(command(draft_of("iam")))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::SystemEntry));
    let offered = world.attempts.offered();
    assert_eq!(offered[0].reason.as_str(), "system_entry");
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn a_route_of_the_iam_service_is_a_system_entry_for_a_holder_of_the_global_route_key() {
    let world = route_world(Stores {
        policy: Some(policy_holding(&["iam:route:*"])),
        ..Stores::default()
    });

    let error = handler(&world)
        .handle(command(draft_of("iam")))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::SystemEntry));
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn an_iam_component_that_creates_a_route_of_the_iam_service_meets_the_system_entry() {
    let world = route_world(Stores::default());
    let mut system = command(draft_of("iam"));
    system.actor = iam_domain::ActorRef::System(iam_domain::SystemComponent::Startup);

    let error = handler(&world).handle(system).await.unwrap_err();

    assert!(matches!(error, IamError::SystemEntry));
}

#[tokio::test]
async fn a_refusal_of_the_unit_of_work_is_the_error_of_the_command() {
    let world = route_world(Stores {
        unit_of_work: FakeIamUnitOfWork::failing(),
        ..Stores::default()
    });

    let error = handler(&world)
        .handle(command(draft_of("core")))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}

#[tokio::test]
async fn an_iam_component_holds_every_route_key_so_a_route_of_the_iam_service_is_a_system_entry() {
    let world = route_world(Stores {
        upstreams: vec![upstream_named(upstream_id(), "iam-control", "iam", 1)],
        ..Stores::default()
    });
    let mut system = command(draft_of("iam"));
    system.actor = iam_domain::ActorRef::System(iam_domain::SystemComponent::Startup);

    let error = handler(&world).handle(system).await.unwrap_err();

    assert!(matches!(error, IamError::SystemEntry));
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[test]
fn the_accepting_compiler_of_the_fixtures_matches_no_request() {
    use iam_domain::{RouteHost, RouteTableCompiler as _};

    let matcher = FakeRouteTableCompiler::new()
        .compile(&RouteHost::new("app.example.test").unwrap(), &[])
        .unwrap();

    assert_eq!(matcher.find(HttpMethod::Get, "/api/orders/1"), None);
}

#[tokio::test]
async fn a_calling_service_without_the_iam_route_key_is_forbidden_a_route_of_the_iam_service() {
    let world = route_world(Stores {
        upstreams: vec![upstream_named(upstream_id(), "iam-control", "iam", 1)],
        ..Stores::default()
    });
    let mut service = command(draft_of("iam"));
    service.actor = iam_domain::ActorRef::Service(ServiceName::new("billing").unwrap());

    let error = handler(&world).handle(service).await.unwrap_err();

    assert!(matches!(error, IamError::Forbidden));
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

fn system_route_on_the_host() -> iam_domain::RouteParts {
    let mut system = route_at(
        numbered_id(9),
        "/api/{rest:*}",
        &[HttpMethod::Get, HttpMethod::Post],
        1,
    );
    system.system = true;
    system
}

#[tokio::test]
async fn a_route_on_the_host_of_the_seeded_iam_routes_is_a_system_entry_and_audited() {
    let world = route_world(Stores {
        routes: vec![system_route_on_the_host()],
        policy: Some(policy_holding(&["iam:route:core"])),
        ..Stores::default()
    });

    let error = handler(&world)
        .handle(command(draft_of("core")))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::SystemEntry), "{error:?}");
    let offered = world.attempts.offered();
    let [attempt] = offered.as_slice() else {
        panic!("one attempt expected: {offered:?}");
    };
    assert_eq!(attempt.action.as_str(), "route.create");
    assert_eq!(attempt.reason.as_str(), "system_entry");
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn a_route_on_another_host_is_not_reserved_by_the_seeded_iam_routes() {
    let world = route_world(Stores {
        routes: vec![system_route_on_the_host()],
        policy: Some(policy_holding(&["iam:route:core"])),
        ..Stores::default()
    });
    let mut draft = draft_of("core");
    draft.host = "other.example.test".to_owned();

    handler(&world).handle(command(draft)).await.unwrap();

    assert_eq!(world.unit_of_work.committed().len(), 1);
}
