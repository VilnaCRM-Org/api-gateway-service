use std::sync::Arc;

use iam_domain::{ContentHash, OpenApiSpecStatement, ServiceName, SpecStatus};
use shared_domain::{Query as _, QueryHandler as _};
use test_support::openapi_spec::{FakeOpenApiSpecRepository, openapi_spec};
use test_support::seed::TestRng;

use super::{FindOpenApiSpecQuery, FindOpenApiSpecQueryHandler};
use crate::error::IamError;

fn service() -> ServiceName {
    ServiceName::new("billing").unwrap()
}

fn hash(byte: u8) -> ContentHash {
    ContentHash::new(&[byte; 32]).unwrap()
}

fn query(service: ServiceName, byte: u8) -> FindOpenApiSpecQuery {
    FindOpenApiSpecQuery {
        service,
        content_hash: hash(byte),
    }
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(FindOpenApiSpecQuery::NAME, "FindOpenApiSpecQuery");
}

#[tokio::test]
async fn the_version_with_the_hash_is_found_by_its_identifier() {
    let mut rng = TestRng::from_env();
    let repository = Arc::new(FakeOpenApiSpecRepository::new());
    let spec = openapi_spec(&mut rng, &service(), SpecStatus::Draft, hash(1));
    let id = spec.parts().id;
    repository
        .save(&OpenApiSpecStatement::insert(&spec, "document".to_owned()))
        .unwrap();
    let handler = FindOpenApiSpecQueryHandler::new(repository);

    let found = handler.handle(query(service(), 1)).await.unwrap();

    assert_eq!(found, Some(id));
}

#[tokio::test]
async fn another_hash_or_another_service_finds_nothing() {
    let mut rng = TestRng::from_env();
    let repository = Arc::new(FakeOpenApiSpecRepository::new());
    let spec = openapi_spec(&mut rng, &service(), SpecStatus::Draft, hash(1));
    repository
        .save(&OpenApiSpecStatement::insert(&spec, "document".to_owned()))
        .unwrap();
    let handler = FindOpenApiSpecQueryHandler::new(repository);

    let other_hash = handler.handle(query(service(), 2)).await.unwrap();
    let shipping = ServiceName::new("shipping").unwrap();
    let other_service = handler.handle(query(shipping, 1)).await.unwrap();

    assert_eq!(other_hash, None);
    assert_eq!(other_service, None);
}

#[tokio::test]
async fn an_unavailable_repository_is_a_storage_error() {
    let handler = FindOpenApiSpecQueryHandler::new(Arc::new(FakeOpenApiSpecRepository::failing()));

    let error = handler.handle(query(service(), 1)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
