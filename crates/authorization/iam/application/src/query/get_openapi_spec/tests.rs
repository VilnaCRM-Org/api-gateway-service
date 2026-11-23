use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, ContentHash, HttpMethod, OpenApiSpec, OpenApiSpecContent, OpenApiSpecParts,
    OpenApiSpecRepository, OpenApiSpecStatement, PathTemplate, PermissionFlags, RestOperation,
    RestOperationSet, ServiceName, SpecId, SpecStatus,
};
use shared_domain::{Query as _, QueryHandler as _, Uuid};
use test_support::openapi_spec::FakeOpenApiSpecRepository;

use super::{GetOpenApiSpecQuery, GetOpenApiSpecQueryHandler};
use crate::error::IamError;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";

fn spec_id(number: u8) -> SpecId {
    SpecId::parse(&format!("0190f2a8-7b3c-7d4e-8f10-1234567890{number:02x}")).unwrap()
}

fn statement() -> OpenApiSpecStatement {
    let at = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap();
    let mut operations = RestOperationSet::new();
    for path in ["/invoices", "/payments"] {
        operations
            .insert(RestOperation {
                method: HttpMethod::Get,
                template: PathTemplate::from_openapi_path(path).unwrap(),
                label: None,
                flags: PermissionFlags::NONE,
            })
            .unwrap();
    }
    let spec = OpenApiSpec::restore(OpenApiSpecParts {
        id: spec_id(1),
        content: OpenApiSpecContent {
            service: ServiceName::new("billing").unwrap(),
            content_hash: ContentHash::new(&[1; 32]).unwrap(),
            operations,
        },
        status: SpecStatus::Draft,
        uploaded_by: ActorRef::User(Uuid::parse(USER).unwrap()),
        created_at: at,
        activated_at: None,
        retired_at: None,
    });
    OpenApiSpecStatement::insert(&spec, "{\"openapi\":\"3.1.0\"}".to_owned())
}

fn handler() -> GetOpenApiSpecQueryHandler {
    let repository = FakeOpenApiSpecRepository::new();
    repository.save(&statement()).unwrap();
    let specs: Arc<dyn OpenApiSpecRepository> = Arc::new(repository);
    GetOpenApiSpecQueryHandler::new(specs)
}

fn query(id: SpecId, include_document: bool) -> GetOpenApiSpecQuery {
    GetOpenApiSpecQuery {
        id,
        include_document,
    }
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(GetOpenApiSpecQuery::NAME, "GetOpenApiSpecQuery");
}

#[tokio::test]
async fn an_unknown_version_is_none() {
    let summary = handler().handle(query(spec_id(9), true)).await.unwrap();

    assert_eq!(summary, None);
}

#[tokio::test]
async fn a_known_version_is_its_state_and_operation_count_without_the_document() {
    let summary = handler()
        .handle(query(spec_id(1), false))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(summary.spec.id, spec_id(1));
    assert_eq!(summary.operation_count, 2);
    assert_eq!(summary.document, None);
}

#[tokio::test]
async fn the_document_is_returned_when_asked_for() {
    let summary = handler()
        .handle(query(spec_id(1), true))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(summary.document.as_deref(), Some("{\"openapi\":\"3.1.0\"}"));
}

#[tokio::test]
async fn a_failing_repository_is_a_storage_error() {
    let specs: Arc<dyn OpenApiSpecRepository> = Arc::new(FakeOpenApiSpecRepository::failing());
    let handler = GetOpenApiSpecQueryHandler::new(specs);

    let error = handler.handle(query(spec_id(1), false)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)), "{error:?}");
}
