use std::sync::Arc;

use iam_domain::{GraphQlTypeGraph, RestOperationSet, ServiceCatalog, ServiceName};
use test_support::policy_epoch::seeded_policy_epoch;
use test_support::policy_read::FakePolicyReadRepository;

use super::ServiceCatalogLoader;
use crate::error::IamError;

fn service() -> ServiceName {
    ServiceName::new("orders").unwrap()
}

fn catalog() -> ServiceCatalog {
    ServiceCatalog::new(
        service(),
        seeded_policy_epoch(),
        vec![RestOperationSet::new()],
        vec![GraphQlTypeGraph::default()],
    )
}

#[tokio::test]
async fn loads_the_catalogue_of_a_service_with_an_active_version() {
    let repository = FakePolicyReadRepository::new().with_catalog(catalog());
    let loader = ServiceCatalogLoader::new(Arc::new(repository));

    let outcome = loader.load(&service()).await.unwrap();

    assert_eq!(outcome, Some(catalog()));
}

#[tokio::test]
async fn a_service_without_an_active_version_is_absent() {
    let loader = ServiceCatalogLoader::new(Arc::new(FakePolicyReadRepository::new()));

    let outcome = loader.load(&service()).await.unwrap();

    assert!(outcome.is_none());
}

#[tokio::test]
async fn a_failing_repository_is_a_storage_error() {
    let loader = ServiceCatalogLoader::new(Arc::new(FakePolicyReadRepository::failing()));

    let error = loader.load(&service()).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
