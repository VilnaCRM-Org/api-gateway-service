use std::sync::Arc;

use iam_domain::{
    AuditSummary, ChangeStatement, EntityVersion, GatewayStatement, GuardCheck, IamUnitOfWork,
    RejectedAttemptLog, RouteParts, RouteRepository, ServiceName,
};
use shared_domain::{Command as _, CommandHandler as _};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::route::FakeRouteRepository;
use test_support::unit_of_work::FakeIamUnitOfWork;

use super::{DeleteRouteCommand, DeleteRouteCommandHandler, DeleteRoutePorts};
use crate::error::IamError;
use crate::rejected_attempt_fixtures::FakeRejectedAttemptLog;
use crate::route_fixtures::{actor, at, change_id, numbered_id, route, route_id};

struct World {
    unit_of_work: Arc<FakeIamUnitOfWork>,
    attempts: Arc<FakeRejectedAttemptLog>,
    handler: DeleteRouteCommandHandler,
}

fn world_with(routes: FakeRouteRepository, unit_of_work: FakeIamUnitOfWork) -> World {
    let unit_of_work = Arc::new(unit_of_work);
    let attempts = Arc::new(FakeRejectedAttemptLog::new());
    let committing: Arc<dyn IamUnitOfWork> = Arc::<FakeIamUnitOfWork>::clone(&unit_of_work);
    let log: Arc<dyn RejectedAttemptLog> = Arc::<FakeRejectedAttemptLog>::clone(&attempts);
    let routes: Arc<dyn RouteRepository> = Arc::new(routes);
    let handler = DeleteRouteCommandHandler::new(
        DeleteRoutePorts {
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

fn world(stored: RouteParts) -> World {
    world_with(
        FakeRouteRepository::holding(vec![stored]),
        FakeIamUnitOfWork::new(),
    )
}

fn command(version: i64) -> DeleteRouteCommand {
    DeleteRouteCommand {
        change_id: change_id(),
        route_id: route_id(),
        actor: actor(),
        expected: EntityVersion::new(version).unwrap(),
        idempotency: None,
    }
}

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(DeleteRouteCommand::NAME, "DeleteRouteCommand");
}

#[tokio::test]
async fn a_route_at_the_expected_version_is_committed_as_a_tombstone_with_its_event() {
    let world = world(route(3));

    world.handler.handle(command(3)).await.unwrap();

    let committed = world.unit_of_work.committed();
    let [change] = committed.as_slice() else {
        panic!("one change expected: {committed:?}");
    };
    let parts = change.parts();
    assert_eq!(parts.entity_version, EntityVersion::new(4).unwrap());
    let [ChangeStatement::SaveGateway(statement)] = parts.statements.as_slice() else {
        panic!("one gateway statement expected");
    };
    let GatewayStatement::Route(statement) = statement.as_ref() else {
        panic!("a route statement expected");
    };
    assert_eq!(statement.expected(), Some(EntityVersion::new(3).unwrap()));
    assert_eq!(statement.route().deleted_at, Some(at()));
    let types: Vec<&str> = parts
        .events
        .iter()
        .map(|event| event.parts().event_type.as_str())
        .collect();
    assert_eq!(types, ["iam.route.deleted"]);
    assert_eq!(
        change.guard(),
        Some(&GuardCheck::Route {
            services: vec![ServiceName::new("core").unwrap()],
            anonymous_key: false,
        })
    );
    let audit = parts.audit.parts();
    assert_eq!(audit.action.as_str(), "route.delete");
    assert_eq!(
        audit.after.as_ref().map(AuditSummary::as_str),
        Some("service=core anonymous=false enforcement=enforce version=4 deleted=true")
    );
}

#[tokio::test]
async fn a_stale_version_an_unknown_route_and_a_failing_store_commit_nothing() {
    let stale = world(route(3));
    let unknown = world_with(FakeRouteRepository::new(), FakeIamUnitOfWork::new());
    let failing = world_with(
        FakeRouteRepository::holding(vec![route(3)]),
        FakeIamUnitOfWork::failing(),
    );

    let stale_error = stale.handler.handle(command(2)).await.unwrap_err();
    let unknown_error = unknown.handler.handle(command(3)).await.unwrap_err();
    let failing_error = failing.handler.handle(command(3)).await.unwrap_err();

    assert!(matches!(stale_error, IamError::PreconditionFailed));
    assert!(matches!(unknown_error, IamError::NotFound));
    assert!(matches!(failing_error, IamError::Storage(_)));
    assert_eq!(stale.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn a_system_route_is_refused_and_audited_as_a_rejected_attempt() {
    let mut system = route(3);
    system.system = true;
    let world = world(system);

    let error = world.handler.handle(command(3)).await.unwrap_err();

    assert!(matches!(error, IamError::SystemEntry));
    assert_eq!(world.unit_of_work.committed(), Vec::new());
    let offered = world.attempts.offered();
    let [attempt] = offered.as_slice() else {
        panic!("one attempt expected: {offered:?}");
    };
    assert_eq!(attempt.action.as_str(), "route.delete");
    assert_eq!(attempt.reason.as_str(), "system_entry");
    assert_eq!(attempt.target.target_id(), route_id().to_string());
}

#[tokio::test]
async fn another_route_stays_untouched() {
    let world = world_with(
        FakeRouteRepository::holding(vec![route(3)]),
        FakeIamUnitOfWork::new(),
    );

    let error = world
        .handler
        .handle(DeleteRouteCommand {
            route_id: numbered_id(9),
            ..command(3)
        })
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::NotFound));
}
