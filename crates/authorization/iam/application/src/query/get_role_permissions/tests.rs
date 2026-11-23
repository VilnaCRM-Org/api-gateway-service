use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    EntityVersion, PermissionGrant, PermissionGrantSet, RoleId, RoleKind, RoleName, RoleParts,
    RoleRepository,
};
use shared_domain::{Query as _, QueryHandler as _};
use test_support::role::FakeRoleRepository;

use super::{GetRolePermissionsQuery, GetRolePermissionsQueryHandler};
use crate::error::IamError;

fn id(number: u32) -> RoleId {
    RoleId::parse(&format!("0190f2a8-7b3c-7d4e-8f10-{number:012x}")).unwrap()
}

fn parts(number: u32, version: i64, grants: &[&str]) -> RoleParts {
    RoleParts {
        id: id(number),
        name: RoleName::new(format!("Role {number}")).unwrap(),
        description: None,
        kind: RoleKind::Custom,
        grants: PermissionGrantSet::new(
            grants
                .iter()
                .map(|text| PermissionGrant::parse(text).unwrap()),
        )
        .unwrap(),
        version: EntityVersion::new(version).unwrap(),
        created_at: SystemTime::UNIX_EPOCH,
        updated_at: SystemTime::UNIX_EPOCH,
        deleted_at: None,
    }
}

fn handler(roles: FakeRoleRepository) -> GetRolePermissionsQueryHandler {
    let roles: Arc<dyn RoleRepository> = Arc::new(roles);
    GetRolePermissionsQueryHandler::new(roles)
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(GetRolePermissionsQuery::NAME, "GetRolePermissionsQuery");
}

#[tokio::test]
async fn the_grants_of_a_role_come_with_its_version() {
    let handler = handler(FakeRoleRepository::holding(vec![
        parts(1, 1, &[]),
        parts(2, 4, &["rest:core:GET /items", "gql:core:*"]),
    ]));

    let answer = handler
        .handle(GetRolePermissionsQuery { id: id(2) })
        .await
        .unwrap()
        .unwrap();

    assert_eq!(answer.id, id(2));
    assert_eq!(answer.version, EntityVersion::new(4).unwrap());
    let keys: Vec<String> = answer
        .grants
        .iter()
        .map(|grant| grant.grant.to_string())
        .collect();
    assert_eq!(keys, ["gql:core:*", "rest:core:GET /items"]);
    assert!(answer.grants.iter().all(|grant| grant.active));
}

#[tokio::test]
async fn an_unknown_role_is_answered_with_none() {
    let handler = handler(FakeRoleRepository::holding(vec![parts(1, 1, &[])]));

    let answer = handler
        .handle(GetRolePermissionsQuery { id: id(9) })
        .await
        .unwrap();

    assert_eq!(answer, None);
}

#[tokio::test]
async fn a_failing_repository_is_a_storage_error() {
    let handler = handler(FakeRoleRepository::failing());

    let error = handler
        .handle(GetRolePermissionsQuery { id: id(1) })
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
