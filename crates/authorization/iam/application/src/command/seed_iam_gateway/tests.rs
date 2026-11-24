use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ChangeStatement, DecisionEffect, EntityVersion, GatewayStatement, HttpMethod, IamChange,
    IamGatewaySeed, IamUnitOfWork, RouteFields, RouteHost, RouteId, RouteParts, UpstreamFields,
    UpstreamId, UpstreamParts,
};
use shared_domain::{Command as _, CommandHandler as _};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::route::FakeRouteRepository;
use test_support::unit_of_work::FakeIamUnitOfWork;
use test_support::upstream::FakeUpstreamRepository;

use super::{SeedIamGatewayCommand, SeedIamGatewayCommandHandler, SeedMode};
use crate::error::IamError;

const HOST: &str = "iam.example.test";
const UPSTREAM: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890cf";

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn seed() -> IamGatewaySeed {
    IamGatewaySeed::new(RouteHost::new(HOST).unwrap())
}

fn command(mode: SeedMode) -> SeedIamGatewayCommand {
    SeedIamGatewayCommand {
        host: RouteHost::new(HOST).unwrap(),
        mode,
    }
}

fn upstream_id() -> UpstreamId {
    UpstreamId::parse(UPSTREAM).unwrap()
}

fn stored_upstream() -> UpstreamParts {
    let (name, settings) = UpstreamFields::new(
        IamGatewaySeed::UPSTREAM_NAME,
        &IamGatewaySeed::upstream_draft(),
    )
    .unwrap()
    .into_parts();
    UpstreamParts {
        id: upstream_id(),
        name,
        settings,
        system: true,
        version: EntityVersion::INITIAL,
        created_at: SystemTime::UNIX_EPOCH,
        updated_at: SystemTime::UNIX_EPOCH,
        deleted_at: None,
    }
}

fn stored_routes() -> Vec<RouteParts> {
    seed()
        .route_drafts(upstream_id())
        .iter()
        .enumerate()
        .map(|(index, draft)| RouteParts {
            id: RouteId::parse(&format!("0190f2a8-7b3c-7d4e-8f10-{index:012x}")).unwrap(),
            fields: RouteFields::new(draft).unwrap(),
            system: true,
            version: EntityVersion::INITIAL,
            created_at: SystemTime::UNIX_EPOCH,
            updated_at: SystemTime::UNIX_EPOCH,
            deleted_at: None,
        })
        .collect()
}

/// The stored route `route` with a body limit of 1,000 bytes.
fn with_small_body(mut route: RouteParts) -> RouteParts {
    let mut draft = seed()
        .route_drafts(upstream_id())
        .into_iter()
        .find(|draft| draft.path_pattern == route.fields.path_pattern().as_str())
        .unwrap();
    draft.body_limit = 1_000;
    route.fields = RouteFields::new(&draft).unwrap();
    route
}

fn handler(
    upstreams: FakeUpstreamRepository,
    routes: FakeRouteRepository,
    unit_of_work: &Arc<FakeIamUnitOfWork>,
) -> SeedIamGatewayCommandHandler {
    let unit_of_work: Arc<dyn IamUnitOfWork> = Arc::<FakeIamUnitOfWork>::clone(unit_of_work);
    SeedIamGatewayCommandHandler::new(
        Arc::new(upstreams),
        Arc::new(routes),
        unit_of_work,
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    )
}

fn empty(unit_of_work: &Arc<FakeIamUnitOfWork>) -> SeedIamGatewayCommandHandler {
    handler(
        FakeUpstreamRepository::new(),
        FakeRouteRepository::new(),
        unit_of_work,
    )
}

fn complete(unit_of_work: &Arc<FakeIamUnitOfWork>) -> SeedIamGatewayCommandHandler {
    handler(
        FakeUpstreamRepository::holding(vec![stored_upstream()]),
        FakeRouteRepository::holding(stored_routes()),
        unit_of_work,
    )
}

fn gateway_statement(change: &IamChange) -> &GatewayStatement {
    let [ChangeStatement::SaveGateway(statement)] = change.parts().statements.as_slice() else {
        panic!(
            "one gateway statement expected: {:?}",
            change.parts().statements
        );
    };
    statement
}

fn event_types(change: &IamChange) -> Vec<&str> {
    change
        .parts()
        .events
        .iter()
        .map(|event| event.parts().event_type.as_str())
        .collect()
}

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(SeedIamGatewayCommand::NAME, "SeedIamGatewayCommand");
}

#[tokio::test]
async fn an_empty_database_gets_the_upstream_and_four_system_routes_as_separate_changes() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    empty(&unit_of_work)
        .handle(command(SeedMode::Seed))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed.len(), 5);
    let GatewayStatement::Upstream(upstream) = gateway_statement(&committed[0]) else {
        panic!("an upstream statement expected first");
    };
    assert_eq!(upstream.expected(), None);
    assert!(upstream.upstream().system);
    assert_eq!(upstream.upstream().name.as_str(), "iam-control");
    assert_eq!(event_types(&committed[0]), ["iam.upstream.created"]);
    for change in &committed[1..] {
        let GatewayStatement::Route(route) = gateway_statement(change) else {
            panic!("a route statement expected");
        };
        assert_eq!(route.expected(), None);
        assert!(route.route().system);
        assert_eq!(route.route().fields.upstream_id(), upstream.upstream().id);
        assert_eq!(route.route().fields.host().as_str(), HOST);
        assert_eq!(event_types(change), ["iam.route.created"]);
    }
    for change in &committed {
        assert_eq!(change.parts().effect, DecisionEffect::Affected);
        assert_eq!(change.parts().entity_version, EntityVersion::INITIAL);
        assert_eq!(
            change.parts().audit.parts().actor.to_string(),
            "system:bootstrap"
        );
    }
}

#[tokio::test]
async fn the_audit_records_name_the_created_entries() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    empty(&unit_of_work)
        .handle(command(SeedMode::Seed))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let actions: Vec<&str> = committed
        .iter()
        .map(|change| change.parts().audit.parts().action.as_str())
        .collect();
    assert_eq!(
        actions,
        [
            "upstream.create",
            "route.create",
            "route.create",
            "route.create",
            "route.create"
        ]
    );
    assert_eq!(
        committed[0].parts().audit.parts().target.target_type(),
        "upstream"
    );
    assert_eq!(
        committed[1].parts().audit.parts().target.target_type(),
        "route"
    );
}

#[tokio::test]
async fn a_second_run_changes_nothing() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    complete(&unit_of_work)
        .handle(command(SeedMode::Seed))
        .await
        .unwrap();

    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn the_seed_never_changes_an_existing_upstream_or_route() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let mut upstream = stored_upstream();
    let (_name, other) = UpstreamFields::new("iam-control", &{
        let mut draft = IamGatewaySeed::upstream_draft();
        draft.port = 8080;
        draft
    })
    .unwrap()
    .into_parts();
    upstream.settings = other;
    let mut routes = stored_routes();
    let first = routes.remove(0);
    routes.insert(0, with_small_body(first));
    let handler = handler(
        FakeUpstreamRepository::holding(vec![upstream]),
        FakeRouteRepository::holding(routes),
        &unit_of_work,
    );

    handler.handle(command(SeedMode::Seed)).await.unwrap();

    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn only_the_absent_routes_are_inserted_for_the_stored_upstream() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let mut routes = stored_routes();
    routes.truncate(3);
    let handler = handler(
        FakeUpstreamRepository::holding(vec![stored_upstream()]),
        FakeRouteRepository::holding(routes),
        &unit_of_work,
    );

    handler.handle(command(SeedMode::Seed)).await.unwrap();

    let committed = unit_of_work.committed();
    let [change] = committed.as_slice() else {
        panic!("one change expected: {committed:?}");
    };
    let GatewayStatement::Route(route) = gateway_statement(change) else {
        panic!("a route statement expected");
    };
    assert_eq!(route.route().fields.upstream_id(), upstream_id());
    assert_eq!(
        route.route().fields.path_pattern().as_str(),
        "/api/graphql-specs"
    );
}

#[tokio::test]
async fn repair_leaves_a_complete_seed_unchanged() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    complete(&unit_of_work)
        .handle(command(SeedMode::Repair))
        .await
        .unwrap();

    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn repair_restores_a_changed_route_as_a_revocation_class_change() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let mut routes = stored_routes();
    let second = routes.remove(1);
    routes.insert(1, with_small_body(second));
    let handler = handler(
        FakeUpstreamRepository::holding(vec![stored_upstream()]),
        FakeRouteRepository::holding(routes),
        &unit_of_work,
    );

    handler.handle(command(SeedMode::Repair)).await.unwrap();

    let committed = unit_of_work.committed();
    let [change] = committed.as_slice() else {
        panic!("one change expected: {committed:?}");
    };
    assert_eq!(change.parts().effect, DecisionEffect::RevocationClass);
    assert_eq!(
        change.parts().entity_version,
        EntityVersion::new(2).unwrap()
    );
    let GatewayStatement::Route(route) = gateway_statement(change) else {
        panic!("a route statement expected");
    };
    assert_eq!(route.expected(), Some(EntityVersion::INITIAL));
    assert_eq!(route.route().fields.body_limit().bytes(), 6 * 1024 * 1024);
    assert_eq!(event_types(change), ["iam.route.updated"]);
    let audit = change.parts().audit.parts();
    assert_eq!(audit.action.as_str(), "route.update");
    assert_eq!(audit.actor.to_string(), "system:bootstrap");
}

#[tokio::test]
async fn repair_restores_a_changed_upstream() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let mut upstream = stored_upstream();
    let mut draft = IamGatewaySeed::upstream_draft();
    draft.forward_credentials = false;
    let (_name, other) = UpstreamFields::new("iam-control", &draft)
        .unwrap()
        .into_parts();
    upstream.settings = other;
    let handler = handler(
        FakeUpstreamRepository::holding(vec![upstream]),
        FakeRouteRepository::holding(stored_routes()),
        &unit_of_work,
    );

    handler.handle(command(SeedMode::Repair)).await.unwrap();

    let committed = unit_of_work.committed();
    let [change] = committed.as_slice() else {
        panic!("one change expected: {committed:?}");
    };
    assert_eq!(change.parts().effect, DecisionEffect::RevocationClass);
    let GatewayStatement::Upstream(statement) = gateway_statement(change) else {
        panic!("an upstream statement expected");
    };
    assert_eq!(statement.expected(), Some(EntityVersion::INITIAL));
    assert!(statement.upstream().settings.forward_credentials());
    assert_eq!(event_types(change), ["iam.upstream.updated"]);
    assert_eq!(
        change.parts().audit.parts().action.as_str(),
        "upstream.update"
    );
}

#[tokio::test]
async fn repair_inserts_a_deleted_route_again_as_a_revocation_class_change() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let mut routes = stored_routes();
    routes.truncate(3);
    let handler = handler(
        FakeUpstreamRepository::holding(vec![stored_upstream()]),
        FakeRouteRepository::holding(routes),
        &unit_of_work,
    );

    handler.handle(command(SeedMode::Repair)).await.unwrap();

    let committed = unit_of_work.committed();
    let [change] = committed.as_slice() else {
        panic!("one change expected: {committed:?}");
    };
    assert_eq!(change.parts().effect, DecisionEffect::RevocationClass);
    let GatewayStatement::Route(route) = gateway_statement(change) else {
        panic!("a route statement expected");
    };
    assert_eq!(route.expected(), None);
    assert!(route.route().system);
    assert_eq!(change.parts().audit.parts().action.as_str(), "route.create");
}

#[tokio::test]
async fn a_stored_route_that_conflicts_with_a_seeded_one_refuses_the_seed() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let mut conflicting = stored_routes().remove(1);
    let mut draft = seed()
        .route_drafts(upstream_id())
        .into_iter()
        .find(|draft| draft.path_pattern == "/api/graphql")
        .unwrap();
    draft.methods = vec![HttpMethod::Get, HttpMethod::Post];
    conflicting.fields = RouteFields::new(&draft).unwrap();
    let handler = handler(
        FakeUpstreamRepository::holding(vec![stored_upstream()]),
        FakeRouteRepository::holding(vec![conflicting]),
        &unit_of_work,
    );

    let error = handler.handle(command(SeedMode::Seed)).await.unwrap_err();

    assert!(
        matches!(error, IamError::RouteTableConflict { .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_failing_repository_or_unit_of_work_fails_the_seed() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let failing_upstreams = handler(
        FakeUpstreamRepository::failing(),
        FakeRouteRepository::new(),
        &unit_of_work,
    );
    let failing_routes = handler(
        FakeUpstreamRepository::holding(vec![stored_upstream()]),
        FakeRouteRepository::failing(),
        &unit_of_work,
    );
    let failing_commit = handler(
        FakeUpstreamRepository::new(),
        FakeRouteRepository::new(),
        &Arc::new(FakeIamUnitOfWork::failing()),
    );

    for failing in [failing_upstreams, failing_routes, failing_commit] {
        let error = failing.handle(command(SeedMode::Seed)).await.unwrap_err();
        assert!(matches!(error, IamError::Storage(_)), "{error:?}");
    }
    assert_eq!(unit_of_work.committed().len(), 0);
}
