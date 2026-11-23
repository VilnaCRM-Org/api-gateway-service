use std::sync::Arc;

use iam_domain::{PermissionKey, SpecId};
use shared_domain::{Query as _, QueryHandler as _};
use test_support::graphql_permission::FakeGraphQlPermissionRepository;

use super::{GetGraphQlPermissionsCreatedQuery, GetGraphQlPermissionsCreatedQueryHandler};
use crate::error::IamError;

const SPEC: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";

fn spec() -> SpecId {
    SpecId::parse(SPEC).unwrap()
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(
        GetGraphQlPermissionsCreatedQuery::NAME,
        "GetGraphQlPermissionsCreatedQuery"
    );
}

#[tokio::test]
async fn the_keys_of_the_recorded_activation_are_returned() {
    let repository = FakeGraphQlPermissionRepository::new();
    let keys = vec![PermissionKey::parse("gql:billing:Query.invoices").unwrap()];
    repository.record_created_keys(spec(), keys.clone());
    let handler = GetGraphQlPermissionsCreatedQueryHandler::new(Arc::new(repository));

    let found = handler
        .handle(GetGraphQlPermissionsCreatedQuery { spec_id: spec() })
        .await
        .unwrap();

    assert_eq!(found, keys);
}

#[tokio::test]
async fn a_version_without_a_recorded_activation_has_no_keys() {
    let handler = GetGraphQlPermissionsCreatedQueryHandler::new(Arc::new(
        FakeGraphQlPermissionRepository::new(),
    ));

    let found = handler
        .handle(GetGraphQlPermissionsCreatedQuery { spec_id: spec() })
        .await
        .unwrap();

    assert_eq!(found, Vec::<PermissionKey>::new());
}

#[tokio::test]
async fn a_failing_repository_is_a_storage_failure() {
    let handler = GetGraphQlPermissionsCreatedQueryHandler::new(Arc::new(
        FakeGraphQlPermissionRepository::failing(),
    ));

    let error = handler
        .handle(GetGraphQlPermissionsCreatedQuery { spec_id: spec() })
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
