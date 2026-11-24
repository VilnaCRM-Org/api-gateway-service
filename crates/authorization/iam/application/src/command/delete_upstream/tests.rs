use std::sync::Arc;

use iam_domain::{
    AuditSummary, ChangeStatement, DecisionEffect, EntityVersion, GatewayPrecondition,
    GatewayStatement, GuardCheck, IamUnitOfWork, IdempotencyKey, IdempotencyRequest,
    RejectedAttemptLog, RequestDigest, RouteParts, RouteRepository, ServiceName, UpstreamParts,
    UpstreamRepository,
};
use shared_domain::{Command as _, CommandHandler as _};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::route::{FakeRouteRepository, route, route_draft};
use test_support::seed::TestRng;
use test_support::unit_of_work::FakeIamUnitOfWork;
use test_support::upstream::FakeUpstreamRepository;

use super::{DeleteUpstreamCommand, DeleteUpstreamCommandHandler, DeleteUpstreamPorts};
use crate::error::IamError;
use crate::rejected_attempt_fixtures::FakeRejectedAttemptLog;
use crate::upstream_fixtures::{
    UPSTREAM, actor, at, change_id, upstream, upstream_id, upstream_named,
};

struct World {
    unit_of_work: Arc<FakeIamUnitOfWork>,
    attempts: Arc<FakeRejectedAttemptLog>,
    handler: DeleteUpstreamCommandHandler,
}

fn world_with(
    upstreams: FakeUpstreamRepository,
    routes: FakeRouteRepository,
    unit_of_work: FakeIamUnitOfWork,
) -> World {
    let unit_of_work = Arc::new(unit_of_work);
    let attempts = Arc::new(FakeRejectedAttemptLog::new());
    let committing: Arc<dyn IamUnitOfWork> = Arc::<FakeIamUnitOfWork>::clone(&unit_of_work);
    let log: Arc<dyn RejectedAttemptLog> = Arc::<FakeRejectedAttemptLog>::clone(&attempts);
    let upstreams: Arc<dyn UpstreamRepository> = Arc::new(upstreams);
    let routes: Arc<dyn RouteRepository> = Arc::new(routes);
    let handler = DeleteUpstreamCommandHandler::new(
        DeleteUpstreamPorts {
            upstreams,
            routes,
            unit_of_work: committing,
            rejected_attempts: log,
        },
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );
    World {
        unit_of_work,
        attempts,
        handler,
    }
}

fn world(stored: UpstreamParts) -> World {
    world_with(
        FakeUpstreamRepository::holding(vec![stored]),
        FakeRouteRepository::new(),
        FakeIamUnitOfWork::new(),
    )
}

fn command(version: i64) -> DeleteUpstreamCommand {
    DeleteUpstreamCommand {
        change_id: change_id(),
        upstream_id: upstream_id(),
        actor: actor(),
        expected: EntityVersion::new(version).unwrap(),
        idempotency: None,
    }
}

fn route_to_upstream() -> RouteParts {
    let draft = route_draft(
        "app.example.test",
        "/api/orders",
        &[iam_domain::HttpMethod::Get],
        "core",
        upstream_id(),
    );
    route(&mut TestRng::from_seed(3), &draft).parts().clone()
}

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(DeleteUpstreamCommand::NAME, "DeleteUpstreamCommand");
}

#[tokio::test]
async fn an_unreferenced_upstream_is_deleted_with_its_event_and_audit_record() {
    let world = world(upstream(1));

    world.handler.handle(command(1)).await.unwrap();

    let committed = world.unit_of_work.committed();
    let [change] = committed.as_slice() else {
        panic!("one change expected: {committed:?}");
    };
    let parts = change.parts();
    assert_eq!(parts.effect, DecisionEffect::Affected);
    assert_eq!(parts.entity_version, EntityVersion::new(2).unwrap());
    let [
        ChangeStatement::ExpectGateway(precondition),
        ChangeStatement::SaveGateway(statement),
    ] = parts.statements.as_slice()
    else {
        panic!(
            "a reference check and one gateway statement expected: {:?}",
            parts.statements
        );
    };
    assert_eq!(
        precondition.as_ref(),
        &GatewayPrecondition::UpstreamUnreferenced(upstream_id())
    );
    let GatewayStatement::Upstream(statement) = statement.as_ref() else {
        panic!("an upstream statement expected: {statement:?}");
    };
    assert_eq!(statement.expected(), Some(EntityVersion::INITIAL));
    assert_eq!(statement.upstream().deleted_at, Some(at()));
    assert_eq!(statement.upstream().version, EntityVersion::new(2).unwrap());
    let types: Vec<&str> = parts
        .events
        .iter()
        .map(|event| event.parts().event_type.as_str())
        .collect();
    assert_eq!(types, ["iam.upstream.deleted"]);
    assert_eq!(
        change.guard(),
        Some(&GuardCheck::RouteScope {
            services: vec![ServiceName::new("core").unwrap()]
        })
    );
    assert_eq!(world.attempts.offered(), Vec::new());
}

#[tokio::test]
async fn the_audit_record_names_both_versions_and_the_deletion() {
    let world = world(upstream(1));

    world.handler.handle(command(1)).await.unwrap();

    let committed = world.unit_of_work.committed();
    let audit = committed[0].parts().audit.parts();
    assert_eq!(audit.action.as_str(), "upstream.delete");
    assert_eq!(audit.target.target_type(), "upstream");
    assert_eq!(audit.target.target_id(), UPSTREAM);
    assert_eq!(audit.actor, actor());
    assert_eq!(audit.occurred_at, at());
    assert_eq!(
        audit.before.as_ref().map(AuditSummary::as_str),
        Some("catalogService=core version=1")
    );
    assert_eq!(
        audit.after.as_ref().map(AuditSummary::as_str),
        Some("catalogService=core version=2 deleted=true")
    );
}

#[tokio::test]
async fn an_idempotency_key_is_kept_on_the_change_and_the_audit_record() {
    let world = world(upstream(1));
    let request = IdempotencyRequest {
        key: IdempotencyKey::new("delete-core").unwrap(),
        request_digest: RequestDigest::new(&[7_u8; 32]).unwrap(),
    };
    let mut with_key = command(1);
    with_key.idempotency = Some(request.clone());

    world.handler.handle(with_key).await.unwrap();

    let committed = world.unit_of_work.committed();
    assert_eq!(committed[0].parts().idempotency, Some(request.clone()));
    assert_eq!(
        committed[0].parts().audit.parts().idempotency_key,
        Some(request.key)
    );
}

#[tokio::test]
async fn an_upstream_that_a_route_references_is_refused_with_a_conflict() {
    let world = world_with(
        FakeUpstreamRepository::holding(vec![upstream(1)]),
        FakeRouteRepository::holding(vec![route_to_upstream()]),
        FakeIamUnitOfWork::new(),
    );

    let error = world.handler.handle(command(1)).await.unwrap_err();

    assert!(matches!(error, IamError::ReferencedByRoute));
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn an_unknown_upstream_is_not_found() {
    let world = world_with(
        FakeUpstreamRepository::new(),
        FakeRouteRepository::new(),
        FakeIamUnitOfWork::new(),
    );

    let error = world.handler.handle(command(1)).await.unwrap_err();

    assert!(matches!(error, IamError::NotFound));
}

#[tokio::test]
async fn a_stale_version_is_a_failed_precondition_and_commits_nothing() {
    let world = world(upstream(3));

    let error = world.handler.handle(command(2)).await.unwrap_err();

    assert!(matches!(error, IamError::PreconditionFailed));
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn a_system_upstream_and_one_of_the_iam_service_are_refused_and_audited() {
    let mut system = upstream(1);
    system.system = true;
    let flagged = world(system);
    let iam = world(upstream_named(upstream_id(), "iam-control", "iam", 1));

    for world in [&flagged, &iam] {
        let error = world.handler.handle(command(1)).await.unwrap_err();

        assert!(matches!(error, IamError::SystemEntry));
        assert_eq!(world.unit_of_work.committed(), Vec::new());
        let offered = world.attempts.offered();
        let [attempt] = offered.as_slice() else {
            panic!("one attempt expected: {offered:?}");
        };
        assert_eq!(attempt.action.as_str(), "upstream.delete");
        assert_eq!(attempt.reason.as_str(), "system_entry");
        assert_eq!(attempt.target.target_id(), UPSTREAM);
    }
}

#[tokio::test]
async fn a_storage_failure_is_the_error_of_the_command() {
    let upstreams = world_with(
        FakeUpstreamRepository::failing(),
        FakeRouteRepository::new(),
        FakeIamUnitOfWork::new(),
    );
    let routes = world_with(
        FakeUpstreamRepository::holding(vec![upstream(1)]),
        FakeRouteRepository::failing(),
        FakeIamUnitOfWork::new(),
    );
    let writing = world_with(
        FakeUpstreamRepository::holding(vec![upstream(1)]),
        FakeRouteRepository::new(),
        FakeIamUnitOfWork::failing(),
    );

    for world in [upstreams, routes, writing] {
        let error = world.handler.handle(command(1)).await.unwrap_err();

        assert!(matches!(error, IamError::Storage(_)), "{error:?}");
    }
}
