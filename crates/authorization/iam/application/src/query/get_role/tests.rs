use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    EntityVersion, PermissionGrantSet, RoleId, RoleKind, RoleName, RoleParts, RoleRepository,
};
use shared_domain::{Query as _, QueryHandler as _};
use test_support::role::FakeRoleRepository;

use super::{GetRoleQuery, GetRoleQueryHandler};
use crate::error::IamError;

fn id(number: u32) -> RoleId {
    RoleId::parse(&format!("0190f2a8-7b3c-7d4e-8f10-{number:012x}")).unwrap()
}

fn parts(number: u32, deleted: bool) -> RoleParts {
    RoleParts {
        id: id(number),
        name: RoleName::new(format!("Role {number}")).unwrap(),
        description: None,
        kind: RoleKind::Custom,
        grants: PermissionGrantSet::default(),
        version: EntityVersion::INITIAL,
        created_at: SystemTime::UNIX_EPOCH,
        updated_at: SystemTime::UNIX_EPOCH,
        deleted_at: deleted.then_some(SystemTime::UNIX_EPOCH),
    }
}

fn handler(roles: FakeRoleRepository) -> GetRoleQueryHandler {
    let roles: Arc<dyn RoleRepository> = Arc::new(roles);
    GetRoleQueryHandler::new(roles)
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(GetRoleQuery::NAME, "GetRoleQuery");
}

#[tokio::test]
async fn a_stored_role_is_answered_with_its_state() {
    let handler = handler(FakeRoleRepository::holding(vec![
        parts(1, false),
        parts(2, false),
    ]));

    let answer = handler.handle(GetRoleQuery { id: id(2) }).await.unwrap();

    assert_eq!(answer, Some(parts(2, false)));
}

#[tokio::test]
async fn an_unknown_role_is_answered_with_none() {
    let handler = handler(FakeRoleRepository::holding(vec![parts(1, false)]));

    let answer = handler.handle(GetRoleQuery { id: id(9) }).await.unwrap();

    assert_eq!(answer, None);
}

#[tokio::test]
async fn a_deleted_role_is_answered_with_none() {
    let handler = handler(FakeRoleRepository::holding(vec![parts(1, true)]));

    let answer = handler.handle(GetRoleQuery { id: id(1) }).await.unwrap();

    assert_eq!(answer, None);
}

#[tokio::test]
async fn a_failing_repository_is_a_storage_failure() {
    let handler = handler(FakeRoleRepository::failing());

    let error = handler
        .handle(GetRoleQuery { id: id(1) })
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)), "{error:?}");
}
