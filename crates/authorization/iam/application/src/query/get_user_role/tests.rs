use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AssignmentExpiry, AssignmentScope, EntityVersion, PermissionGrantSet, RoleId,
    RoleKind, RoleName, RoleParts, RoleRepository, SubjectRef, UserRoleId, UserRoleParts,
    UserRoleRepository,
};
use shared_domain::{Query as _, QueryHandler as _, Uuid};
use test_support::role::FakeRoleRepository;
use test_support::user_role::FakeUserRoleRepository;

use super::{GetUserRoleQuery, GetUserRoleQueryHandler, UserRoleView};
use crate::error::IamError;

fn role_id(number: u32) -> RoleId {
    RoleId::parse(&format!("0190f2a8-7b3c-7d4e-8f10-{number:012x}")).unwrap()
}

fn id(number: u32) -> UserRoleId {
    UserRoleId::parse(&format!("0190f2a8-7b3c-7d4e-8f11-{number:012x}")).unwrap()
}

fn role(number: u32) -> RoleParts {
    RoleParts {
        id: role_id(number),
        name: RoleName::new(format!("Role {number}")).unwrap(),
        description: None,
        kind: RoleKind::Custom,
        grants: PermissionGrantSet::default(),
        version: EntityVersion::INITIAL,
        created_at: SystemTime::UNIX_EPOCH,
        updated_at: SystemTime::UNIX_EPOCH,
        deleted_at: None,
    }
}

fn parts(number: u32, role: u32) -> UserRoleParts {
    UserRoleParts {
        id: id(number),
        subject: SubjectRef::user(Uuid::parse("0190f2a8-7b3c-7d4e-8f12-000000000001").unwrap()),
        role_id: role_id(role),
        scope: AssignmentScope::Global,
        expires_at: None,
        version: EntityVersion::INITIAL,
        created_by: ActorRef::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f12-000000000002").unwrap()),
        created_at: SystemTime::UNIX_EPOCH,
        updated_at: SystemTime::UNIX_EPOCH,
        revoked_at: None,
    }
}

fn handler(
    user_roles: FakeUserRoleRepository,
    roles: FakeRoleRepository,
) -> GetUserRoleQueryHandler {
    let user_roles: Arc<dyn UserRoleRepository> = Arc::new(user_roles);
    let roles: Arc<dyn RoleRepository> = Arc::new(roles);
    GetUserRoleQueryHandler::new(user_roles, roles)
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(GetUserRoleQuery::NAME, "GetUserRoleQuery");
}

#[tokio::test]
async fn a_stored_assignment_is_answered_with_the_name_of_its_role() {
    let handler = handler(
        FakeUserRoleRepository::holding(vec![parts(1, 1), parts(2, 2)]),
        FakeRoleRepository::holding(vec![role(1), role(2)]),
    );

    let answer = handler
        .handle(GetUserRoleQuery { id: id(2) })
        .await
        .unwrap();

    assert_eq!(
        answer,
        Some(UserRoleView {
            user_role: parts(2, 2),
            role_name: Some(RoleName::new("Role 2".to_owned()).unwrap()),
        })
    );
}

#[tokio::test]
async fn an_expired_assignment_is_still_answered() {
    let expired = UserRoleParts {
        expires_at: Some(AssignmentExpiry::restore(
            SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(5))
                .unwrap(),
        )),
        ..parts(1, 1)
    };
    let handler = handler(
        FakeUserRoleRepository::holding(vec![expired.clone()]),
        FakeRoleRepository::holding(vec![role(1)]),
    );

    let answer = handler
        .handle(GetUserRoleQuery { id: id(1) })
        .await
        .unwrap();

    assert_eq!(answer.map(|view| view.user_role), Some(expired));
}

#[tokio::test]
async fn an_assignment_whose_role_is_gone_is_answered_without_a_role_name() {
    let handler = handler(
        FakeUserRoleRepository::holding(vec![parts(1, 9)]),
        FakeRoleRepository::new(),
    );

    let answer = handler
        .handle(GetUserRoleQuery { id: id(1) })
        .await
        .unwrap();

    assert_eq!(answer.map(|view| view.role_name), Some(None));
}

#[tokio::test]
async fn an_unknown_assignment_is_none() {
    let handler = handler(
        FakeUserRoleRepository::holding(vec![parts(1, 1)]),
        FakeRoleRepository::holding(vec![role(1)]),
    );

    let answer = handler
        .handle(GetUserRoleQuery { id: id(7) })
        .await
        .unwrap();

    assert_eq!(answer, None);
}

#[tokio::test]
async fn a_revoked_assignment_is_none() {
    let revoked = UserRoleParts {
        revoked_at: Some(SystemTime::UNIX_EPOCH),
        ..parts(1, 1)
    };
    let handler = handler(
        FakeUserRoleRepository::holding(vec![revoked]),
        FakeRoleRepository::holding(vec![role(1)]),
    );

    let answer = handler
        .handle(GetUserRoleQuery { id: id(1) })
        .await
        .unwrap();

    assert_eq!(answer, None);
}

#[tokio::test]
async fn an_unreadable_assignment_store_is_a_storage_failure() {
    let handler = handler(FakeUserRoleRepository::failing(), FakeRoleRepository::new());

    let error = handler
        .handle(GetUserRoleQuery { id: id(1) })
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)), "{error:?}");
}

#[tokio::test]
async fn an_unreadable_role_store_is_a_storage_failure() {
    let handler = handler(
        FakeUserRoleRepository::holding(vec![parts(1, 1)]),
        FakeRoleRepository::failing(),
    );

    let error = handler
        .handle(GetUserRoleQuery { id: id(1) })
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)), "{error:?}");
}
