use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, ContentHash, HttpMethod, OpenApiSpec, OpenApiSpecContent, OpenApiSpecParts,
    OpenApiSpecRepository, OpenApiSpecStatement, PathTemplate, PermissionFlags, RestOperation,
    RestOperationSet, ServiceName, SpecId, SpecStatus,
};
use shared_domain::{Query as _, QueryHandler as _, Uuid};
use test_support::openapi_spec::FakeOpenApiSpecRepository;

use super::{GetOpenApiSpecsQuery, GetOpenApiSpecsQueryHandler, MAX_PAGE_SIZE, OpenApiSpecPage};
use crate::error::IamError;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";

fn spec_id(number: u8) -> SpecId {
    SpecId::parse(&format!("0190f2a8-7b3c-7d4e-8f10-1234567890{number:02x}")).unwrap()
}

fn operations(paths: &[&str]) -> RestOperationSet {
    let mut set = RestOperationSet::new();
    for path in paths {
        set.insert(RestOperation {
            method: HttpMethod::Get,
            template: PathTemplate::from_openapi_path(path).unwrap(),
            label: None,
            flags: PermissionFlags::NONE,
        })
        .unwrap();
    }
    set
}

fn statement(
    number: u8,
    service: &str,
    status: SpecStatus,
    paths: &[&str],
) -> OpenApiSpecStatement {
    let at = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap();
    let spec = OpenApiSpec::restore(OpenApiSpecParts {
        id: spec_id(number),
        content: OpenApiSpecContent {
            service: ServiceName::new(service).unwrap(),
            content_hash: ContentHash::new(&[number; 32]).unwrap(),
            operations: operations(paths),
        },
        status,
        uploaded_by: ActorRef::User(Uuid::parse(USER).unwrap()),
        created_at: at,
        activated_at: (status != SpecStatus::Draft).then_some(at),
        retired_at: None,
    });
    OpenApiSpecStatement::insert(&spec, format!("document {number}"))
}

fn handler(statements: &[OpenApiSpecStatement]) -> GetOpenApiSpecsQueryHandler {
    let repository = FakeOpenApiSpecRepository::new();
    for statement in statements {
        repository.save(statement).unwrap();
    }
    let specs: Arc<dyn OpenApiSpecRepository> = Arc::new(repository);
    GetOpenApiSpecsQueryHandler::new(specs)
}

fn numbered(count: u8) -> Vec<OpenApiSpecStatement> {
    (1..=count)
        .map(|number| statement(number, "billing", SpecStatus::Draft, &["/a"]))
        .collect()
}

fn query(limit: u32) -> GetOpenApiSpecsQuery {
    GetOpenApiSpecsQuery {
        limit,
        after: None,
        service: None,
        status: None,
        include_document: false,
    }
}

fn ids(page: &OpenApiSpecPage) -> Vec<SpecId> {
    page.specs.iter().map(|summary| summary.spec.id).collect()
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(GetOpenApiSpecsQuery::NAME, "GetOpenApiSpecsQuery");
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
            .handle(GetOpenApiSpecsQuery { after, ..query(2) })
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
        OpenApiSpecPage {
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
        .map(|number: u8| statement(number, "billing", SpecStatus::Draft, &["/a"]))
        .collect();
    let handler = handler(&statements);

    let page = handler.handle(query(1_000)).await.unwrap();

    assert_eq!(page.specs.len(), 100);
    assert_eq!(page.next_after, Some(spec_id(100)));
}

#[tokio::test]
async fn the_filters_narrow_the_page_by_service_and_status() {
    let handler = handler(&[
        statement(1, "billing", SpecStatus::Draft, &["/a"]),
        statement(2, "billing", SpecStatus::Active, &["/a"]),
        statement(3, "shipping", SpecStatus::Active, &["/a"]),
    ]);

    let by_service = handler
        .handle(GetOpenApiSpecsQuery {
            service: Some(ServiceName::new("billing").unwrap()),
            ..query(10)
        })
        .await
        .unwrap();
    let by_status = handler
        .handle(GetOpenApiSpecsQuery {
            status: Some(SpecStatus::Active),
            ..query(10)
        })
        .await
        .unwrap();
    let by_both = handler
        .handle(GetOpenApiSpecsQuery {
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
async fn a_summary_carries_the_state_and_the_operation_count_without_the_document() {
    let handler = handler(&[statement(1, "billing", SpecStatus::Draft, &["/a", "/b"])]);

    let page = handler.handle(query(10)).await.unwrap();

    let summary = &page.specs[0];
    assert_eq!(summary.spec.id, spec_id(1));
    assert_eq!(summary.spec.status, SpecStatus::Draft);
    assert_eq!(summary.operation_count, 2);
    assert_eq!(summary.document, None);
}

#[tokio::test]
async fn the_document_is_read_only_when_asked_for() {
    let handler = handler(&numbered(2));

    let page = handler
        .handle(GetOpenApiSpecsQuery {
            include_document: true,
            ..query(10)
        })
        .await
        .unwrap();

    let documents: Vec<_> = page
        .specs
        .iter()
        .map(|summary| summary.document.clone())
        .collect();
    assert_eq!(
        documents,
        [Some("document 1".to_owned()), Some("document 2".to_owned())]
    );
}

#[tokio::test]
async fn a_failing_repository_is_a_storage_error() {
    let specs: Arc<dyn OpenApiSpecRepository> = Arc::new(FakeOpenApiSpecRepository::failing());
    let handler = GetOpenApiSpecsQueryHandler::new(specs);

    let error = handler.handle(query(10)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)), "{error:?}");
}
