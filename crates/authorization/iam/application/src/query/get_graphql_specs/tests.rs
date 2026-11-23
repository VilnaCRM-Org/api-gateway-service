use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, ContentHash, GqlName, GraphQlCoordinate, GraphQlField, GraphQlSpec,
    GraphQlSpecContent, GraphQlSpecParts, GraphQlSpecRepository, GraphQlSpecStatement,
    GraphQlTypeGraph, PermissionFlags, ServiceName, SpecId, SpecStatus,
};
use shared_domain::{Query as _, QueryHandler as _, Uuid};
use test_support::graphql_spec::FakeGraphQlSpecRepository;

use super::{GetGraphQlSpecsQuery, GetGraphQlSpecsQueryHandler, GraphQlSpecPage, MAX_PAGE_SIZE};
use crate::error::IamError;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";

fn spec_id(number: u8) -> SpecId {
    SpecId::parse(&format!("0190f2a8-7b3c-7d4e-8f10-1234567890{number:02x}")).unwrap()
}

fn type_graph(coordinates: &[&str]) -> GraphQlTypeGraph {
    GraphQlTypeGraph::new(
        coordinates.iter().map(|text| {
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
    .unwrap()
}

fn statement(
    number: u8,
    service: &str,
    status: SpecStatus,
    coordinates: &[&str],
) -> GraphQlSpecStatement {
    let at = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap();
    let spec = GraphQlSpec::restore(GraphQlSpecParts {
        id: spec_id(number),
        content: GraphQlSpecContent {
            service: ServiceName::new(service).unwrap(),
            content_hash: ContentHash::new(&[number; 32]).unwrap(),
            type_graph: type_graph(coordinates),
        },
        status,
        uploaded_by: ActorRef::User(Uuid::parse(USER).unwrap()),
        created_at: at,
        activated_at: (status != SpecStatus::Draft).then_some(at),
        retired_at: None,
    });
    GraphQlSpecStatement::insert(&spec, format!("sdl {number}"))
}

fn handler(statements: &[GraphQlSpecStatement]) -> GetGraphQlSpecsQueryHandler {
    let repository = FakeGraphQlSpecRepository::new();
    for statement in statements {
        repository.save(statement).unwrap();
    }
    let specs: Arc<dyn GraphQlSpecRepository> = Arc::new(repository);
    GetGraphQlSpecsQueryHandler::new(specs)
}

fn numbered(count: u8) -> Vec<GraphQlSpecStatement> {
    (1..=count)
        .map(|number| statement(number, "billing", SpecStatus::Draft, &["Query.a"]))
        .collect()
}

fn query(limit: u32) -> GetGraphQlSpecsQuery {
    GetGraphQlSpecsQuery {
        limit,
        after: None,
        service: None,
        status: None,
        include_sdl: false,
    }
}

fn ids(page: &GraphQlSpecPage) -> Vec<SpecId> {
    page.specs.iter().map(|summary| summary.spec.id).collect()
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(GetGraphQlSpecsQuery::NAME, "GetGraphQlSpecsQuery");
}

#[test]
fn the_largest_page_holds_a_hundred_versions() {
    assert_eq!(MAX_PAGE_SIZE, 100);
}

#[tokio::test]
async fn a_page_smaller_than_the_stock_names_the_last_version_as_its_cursor() {
    let handler = handler(&numbered(5));

    let page = handler.handle(query(2)).await.unwrap();

    assert_eq!(ids(&page), [spec_id(1), spec_id(2)]);
    assert_eq!(page.next_after, Some(spec_id(2)));
}

#[tokio::test]
async fn following_the_cursors_visits_every_version_exactly_once() {
    let handler = handler(&numbered(5));
    let mut seen = Vec::new();
    let mut after = None;

    loop {
        let page = handler
            .handle(GetGraphQlSpecsQuery { after, ..query(2) })
            .await
            .unwrap();
        seen.extend(ids(&page));
        after = page.next_after;
        if after.is_none() {
            break;
        }
    }

    assert_eq!(
        seen,
        [spec_id(1), spec_id(2), spec_id(3), spec_id(4), spec_id(5)]
    );
}

#[tokio::test]
async fn a_stock_that_fits_the_page_has_no_cursor() {
    let handler = handler(&numbered(2));

    let page = handler.handle(query(2)).await.unwrap();

    assert_eq!(page.specs.len(), 2);
    assert_eq!(page.next_after, None);
}

#[tokio::test]
async fn no_version_is_an_empty_page_without_a_cursor() {
    let handler = handler(&[]);

    let page = handler.handle(query(10)).await.unwrap();

    assert_eq!(
        page,
        GraphQlSpecPage {
            specs: Vec::new(),
            next_after: None
        }
    );
}

#[tokio::test]
async fn a_limit_of_zero_is_brought_up_to_one() {
    let handler = handler(&numbered(3));

    let page = handler.handle(query(0)).await.unwrap();

    assert_eq!(ids(&page), [spec_id(1)]);
    assert_eq!(page.next_after, Some(spec_id(1)));
}

#[tokio::test]
async fn a_limit_over_the_maximum_is_brought_down_to_it() {
    let statements: Vec<_> = (1..=101)
        .map(|number: u8| statement(number, "billing", SpecStatus::Draft, &["Query.a"]))
        .collect();
    let handler = handler(&statements);

    let page = handler.handle(query(1_000)).await.unwrap();

    assert_eq!(page.specs.len(), 100);
    assert_eq!(page.next_after, Some(spec_id(100)));
}

#[tokio::test]
async fn the_filters_narrow_the_page_by_service_and_status() {
    let handler = handler(&[
        statement(1, "billing", SpecStatus::Draft, &["Query.a"]),
        statement(2, "billing", SpecStatus::Active, &["Query.a"]),
        statement(3, "shipping", SpecStatus::Active, &["Query.a"]),
    ]);

    let by_service = handler
        .handle(GetGraphQlSpecsQuery {
            service: Some(ServiceName::new("billing").unwrap()),
            ..query(10)
        })
        .await
        .unwrap();
    let by_status = handler
        .handle(GetGraphQlSpecsQuery {
            status: Some(SpecStatus::Active),
            ..query(10)
        })
        .await
        .unwrap();
    let by_both = handler
        .handle(GetGraphQlSpecsQuery {
            service: Some(ServiceName::new("shipping").unwrap()),
            status: Some(SpecStatus::Active),
            ..query(10)
        })
        .await
        .unwrap();

    assert_eq!(ids(&by_service), [spec_id(1), spec_id(2)]);
    assert_eq!(ids(&by_status), [spec_id(2), spec_id(3)]);
    assert_eq!(ids(&by_both), [spec_id(3)]);
}

#[tokio::test]
async fn a_summary_carries_the_state_and_the_coordinate_count_without_the_sdl() {
    let handler = handler(&[statement(
        1,
        "billing",
        SpecStatus::Draft,
        &["Query.a", "Query.b"],
    )]);

    let page = handler.handle(query(10)).await.unwrap();

    let summary = &page.specs[0];
    assert_eq!(summary.spec.id, spec_id(1));
    assert_eq!(summary.spec.status, SpecStatus::Draft);
    assert_eq!(summary.coordinate_count, 2);
    assert_eq!(summary.sdl, None);
}

#[tokio::test]
async fn the_sdl_is_read_only_when_asked_for() {
    let handler = handler(&numbered(2));

    let page = handler
        .handle(GetGraphQlSpecsQuery {
            include_sdl: true,
            ..query(10)
        })
        .await
        .unwrap();

    let sdls: Vec<_> = page
        .specs
        .iter()
        .map(|summary| summary.sdl.clone())
        .collect();
    assert_eq!(sdls, [Some("sdl 1".to_owned()), Some("sdl 2".to_owned())]);
}

#[tokio::test]
async fn a_failing_repository_is_a_storage_error() {
    let specs: Arc<dyn GraphQlSpecRepository> = Arc::new(FakeGraphQlSpecRepository::failing());
    let handler = GetGraphQlSpecsQueryHandler::new(specs);

    let error = handler.handle(query(10)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)), "{error:?}");
}
