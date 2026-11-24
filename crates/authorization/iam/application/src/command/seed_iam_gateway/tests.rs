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

fn squatting_upstream() -> UpstreamParts {
    UpstreamParts {
        system: false,
        ..stored_upstream()
    }
}

fn squatting_routes() -> Vec<RouteParts> {
    let mut routes = stored_routes();
    routes[1].system = false;
    routes
}

#[tokio::test]
async fn seed_refuses_a_non_system_upstream_named_iam_control_and_writes_nothing() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let handler = handler(
        FakeUpstreamRepository::holding(vec![squatting_upstream()]),
        FakeRouteRepository::new(),
        &unit_of_work,
    );

    let error = handler.handle(command(SeedMode::Seed)).await.unwrap_err();

    let IamError::SeedConflict(entries) = error else {
        panic!("a seed conflict expected: {error:?}");
    };
    assert!(entries.contains("upstream iam-control"), "{entries}");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn seed_refuses_a_non_system_route_on_a_seeded_target_and_writes_nothing() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let handler = handler(
        FakeUpstreamRepository::new(),
        FakeRouteRepository::holding(squatting_routes()),
        &unit_of_work,
    );

    let error = handler.handle(command(SeedMode::Seed)).await.unwrap_err();

    let IamError::SeedConflict(entries) = error else {
        panic!("a seed conflict expected: {error:?}");
    };
    assert!(entries.contains("route "), "{entries}");
    assert!(entries.contains("/api/graphql"), "{entries}");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn seed_names_every_occupant_at_once() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let handler = handler(
        FakeUpstreamRepository::holding(vec![squatting_upstream()]),
        FakeRouteRepository::holding(squatting_routes()),
        &unit_of_work,
    );

    let error = handler.handle(command(SeedMode::Seed)).await.unwrap_err();

    let IamError::SeedConflict(entries) = error else {
        panic!("a seed conflict expected: {error:?}");
    };
    assert!(entries.contains("upstream iam-control"), "{entries}");
    assert!(entries.contains("route "), "{entries}");
}

#[tokio::test]
async fn a_non_system_route_of_another_host_is_no_occupant() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let mut elsewhere = squatting_routes();
    let mut draft = seed().route_drafts(upstream_id()).remove(1);
    draft.host = "other.example.test".to_owned();
    elsewhere[1].fields = RouteFields::new(&draft).unwrap();
    let handler = handler(
        FakeUpstreamRepository::holding(vec![stored_upstream()]),
        FakeRouteRepository::holding(elsewhere),
        &unit_of_work,
    );

    handler.handle(command(SeedMode::Seed)).await.unwrap();

    let committed = unit_of_work.committed();
    let [change] = committed.as_slice() else {
        panic!("only the absent seeded route is inserted: {committed:?}");
    };
    assert_eq!(change.parts().audit.parts().action.as_str(), "route.create");
}

#[tokio::test]
async fn repair_replaces_a_non_system_upstream_with_the_system_entry() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let handler = handler(
        FakeUpstreamRepository::holding(vec![squatting_upstream()]),
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
    assert!(statement.upstream().system);
    assert_eq!(statement.upstream().id, upstream_id());
    let audit = change.parts().audit.parts();
    assert_eq!(audit.action.as_str(), "upstream.update");
    assert_eq!(audit.actor.to_string(), "system:bootstrap");
    assert!(
        audit
            .before
            .as_ref()
            .unwrap()
            .as_str()
            .contains("system=false")
    );
    assert!(
        audit
            .after
            .as_ref()
            .unwrap()
            .as_str()
            .contains("system=true")
    );
}

#[tokio::test]
async fn repair_replaces_a_non_system_route_with_the_system_entry() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let handler = handler(
        FakeUpstreamRepository::holding(vec![stored_upstream()]),
        FakeRouteRepository::holding(squatting_routes()),
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
    assert_eq!(route.expected(), Some(EntityVersion::INITIAL));
    assert!(route.route().system);
    assert_eq!(route.route().id, stored_routes()[1].id);
    let audit = change.parts().audit.parts();
    assert_eq!(audit.action.as_str(), "route.update");
    assert!(
        audit
            .before
            .as_ref()
            .unwrap()
            .as_str()
            .contains("system=false")
    );
    assert!(
        audit
            .after
            .as_ref()
            .unwrap()
            .as_str()
            .contains("system=true")
    );
}

#[tokio::test]
async fn repair_restores_a_system_route_that_forwards_to_another_upstream() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let mut routes = stored_routes();
    let mut draft = seed()
        .route_drafts(UpstreamId::parse("0190f2a8-7b3c-7d4e-8f10-1234567890d0").unwrap())
        .remove(0);
    draft.path_pattern = routes[0].fields.path_pattern().to_string();
    routes[0].fields = RouteFields::new(&draft).unwrap();
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
    let GatewayStatement::Route(route) = gateway_statement(change) else {
        panic!("a route statement expected");
    };
    assert_eq!(route.route().fields.upstream_id(), upstream_id());
    assert!(route.route().system);
}

/// A route of a caller on another host that forwards to the occupant of the seeded upstream name.
fn callers_route_to_the_squatter() -> RouteParts {
    let mut draft = seed().route_drafts(upstream_id()).remove(1);
    draft.host = "callers.example.test".to_owned();
    draft.path_pattern = "/stolen".to_owned();
    RouteParts {
        id: RouteId::parse("0190f2a8-7b3c-7d4e-8f10-0000000000aa").unwrap(),
        fields: RouteFields::new(&draft).unwrap(),
        system: false,
        version: EntityVersion::INITIAL,
        created_at: SystemTime::UNIX_EPOCH,
        updated_at: SystemTime::UNIX_EPOCH,
        deleted_at: None,
    }
}

fn routes_with_the_callers_route() -> Vec<RouteParts> {
    let mut routes = stored_routes();
    routes.push(callers_route_to_the_squatter());
    routes
}

#[tokio::test]
async fn seed_names_a_non_system_route_of_another_host_that_forwards_to_the_squatter() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let handler = handler(
        FakeUpstreamRepository::holding(vec![squatting_upstream()]),
        FakeRouteRepository::holding(routes_with_the_callers_route()),
        &unit_of_work,
    );

    let error = handler.handle(command(SeedMode::Seed)).await.unwrap_err();

    let IamError::SeedConflict(entries) = error else {
        panic!("a seed conflict expected: {error:?}");
    };
    assert!(entries.contains("upstream iam-control"), "{entries}");
    assert!(
        entries.contains("callers.example.test /stolen"),
        "{entries}"
    );
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn repair_deletes_the_non_system_routes_of_the_squatter_before_it_becomes_the_system_upstream()
 {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let handler = handler(
        FakeUpstreamRepository::holding(vec![squatting_upstream()]),
        FakeRouteRepository::holding(routes_with_the_callers_route()),
        &unit_of_work,
    );

    handler.handle(command(SeedMode::Repair)).await.unwrap();

    let committed = unit_of_work.committed();
    let [deletion, update] = committed.as_slice() else {
        panic!("a route deletion then an upstream update expected: {committed:?}");
    };
    assert_eq!(deletion.parts().effect, DecisionEffect::RevocationClass);
    let GatewayStatement::Route(route) = gateway_statement(deletion) else {
        panic!("a route statement expected");
    };
    assert_eq!(route.route().id, callers_route_to_the_squatter().id);
    assert!(route.route().deleted_at.is_some());
    assert_eq!(route.expected(), Some(EntityVersion::INITIAL));
    assert_eq!(
        deletion.parts().audit.parts().action.as_str(),
        "route.delete"
    );
    assert_eq!(event_types(deletion), ["iam.route.deleted"]);
    let GatewayStatement::Upstream(statement) = gateway_statement(update) else {
        panic!("an upstream statement expected");
    };
    assert!(statement.upstream().system);
}

#[tokio::test]
async fn repair_of_a_system_upstream_deletes_no_route() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let mut upstream = stored_upstream();
    let mut draft = IamGatewaySeed::upstream_draft();
    draft.port = 8_080;
    upstream.settings = UpstreamFields::new(IamGatewaySeed::UPSTREAM_NAME, &draft)
        .unwrap()
        .into_parts()
        .1;
    let handler = handler(
        FakeUpstreamRepository::holding(vec![upstream]),
        FakeRouteRepository::holding(routes_with_the_callers_route()),
        &unit_of_work,
    );

    handler.handle(command(SeedMode::Repair)).await.unwrap();

    let committed = unit_of_work.committed();
    let [update] = committed.as_slice() else {
        panic!("one upstream update expected: {committed:?}");
    };
    assert!(matches!(
        gateway_statement(update),
        GatewayStatement::Upstream(_)
    ));
}

#[tokio::test]
async fn repair_retires_every_page_of_the_routes_of_the_squatter() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let mut routes = stored_routes();
    let template = callers_route_to_the_squatter();
    for index in 0..101_usize {
        let mut route = template.clone();
        route.id = RouteId::parse(&format!("0190f2a8-7b3c-7d4e-8f11-{index:012x}")).unwrap();
        let mut draft = seed().route_drafts(upstream_id()).remove(1);
        draft.host = "callers.example.test".to_owned();
        draft.path_pattern = format!("/stolen-{index}");
        route.fields = RouteFields::new(&draft).unwrap();
        routes.push(route);
    }
    let handler = handler(
        FakeUpstreamRepository::holding(vec![squatting_upstream()]),
        FakeRouteRepository::holding(routes),
        &unit_of_work,
    );

    handler.handle(command(SeedMode::Repair)).await.unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(
        committed.len(),
        102,
        "101 deletions and the upstream update"
    );
}
