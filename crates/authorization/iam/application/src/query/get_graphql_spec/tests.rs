use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, ContentHash, GqlName, GraphQlCoordinate, GraphQlField, GraphQlSpec,
    GraphQlSpecContent, GraphQlSpecParts, GraphQlSpecRepository, GraphQlSpecStatement,
    GraphQlTypeGraph, PermissionFlags, ServiceName, SpecId, SpecStatus,
};
use shared_domain::{Query as _, QueryHandler as _, Uuid};
use test_support::graphql_spec::FakeGraphQlSpecRepository;

use super::{GetGraphQlSpecQuery, GetGraphQlSpecQueryHandler};
use crate::error::IamError;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";

fn spec_id(number: u8) -> SpecId {
    SpecId::parse(&format!("0190f2a8-7b3c-7d4e-8f10-1234567890{number:02x}")).unwrap()
}

fn statement() -> GraphQlSpecStatement {
    let at = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap();
    let graph = GraphQlTypeGraph::new(
        ["Query.a", "Query.b"].iter().map(|text| {
            (
                GraphQlCoordinate::parse(text).unwrap(),
                GraphQlField {
                    return_type: GqlName::parse("String").unwrap(),
                    flags: PermissionFlags::NONE,
                },
            )
        }),
        [],
    )
    .unwrap();
    let spec = GraphQlSpec::restore(GraphQlSpecParts {
        id: spec_id(1),
        content: GraphQlSpecContent {
            service: ServiceName::new("billing").unwrap(),
            content_hash: ContentHash::new(&[1; 32]).unwrap(),
            type_graph: graph,
        },
        status: SpecStatus::Draft,
        uploaded_by: ActorRef::User(Uuid::parse(USER).unwrap()),
        created_at: at,
        activated_at: None,
        retired_at: None,
    });
    GraphQlSpecStatement::insert(&spec, "type Query { a: String b: String }".to_owned())
}

fn handler() -> GetGraphQlSpecQueryHandler {
    let repository = FakeGraphQlSpecRepository::new();
    repository.save(&statement()).unwrap();
    let specs: Arc<dyn GraphQlSpecRepository> = Arc::new(repository);
    GetGraphQlSpecQueryHandler::new(specs)
}

fn query(id: SpecId, include_sdl: bool) -> GetGraphQlSpecQuery {
    GetGraphQlSpecQuery { id, include_sdl }
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(GetGraphQlSpecQuery::NAME, "GetGraphQlSpecQuery");
}

#[tokio::test]
async fn an_unknown_version_is_none() {
    let summary = handler().handle(query(spec_id(9), true)).await.unwrap();

    assert_eq!(summary, None);
}

#[tokio::test]
async fn a_known_version_is_its_state_and_coordinate_count_without_the_sdl() {
    let summary = handler()
        .handle(query(spec_id(1), false))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(summary.spec.id, spec_id(1));
    assert_eq!(summary.coordinate_count, 2);
    assert_eq!(summary.sdl, None);
}

#[tokio::test]
async fn the_sdl_is_returned_when_asked_for() {
    let summary = handler()
        .handle(query(spec_id(1), true))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        summary.sdl.as_deref(),
        Some("type Query { a: String b: String }")
    );
}

#[tokio::test]
async fn a_failing_repository_is_a_storage_error() {
    let specs: Arc<dyn GraphQlSpecRepository> = Arc::new(FakeGraphQlSpecRepository::failing());
    let handler = GetGraphQlSpecQueryHandler::new(specs);

    let error = handler.handle(query(spec_id(1), false)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)), "{error:?}");
}
