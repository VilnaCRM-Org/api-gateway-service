use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AssignmentExpiry, AssignmentScope, EntityVersion, PermissionGrantSet, ProjectId,
    RoleId, RoleKind, RoleName, RoleParts, RoleRepository, ServiceName, SubjectKind, SubjectRef,
    UserRoleId, UserRoleParts, UserRoleRepository,
};
use shared_domain::{Query as _, QueryHandler as _, Uuid};
use test_support::clock::FixedClock;
use test_support::role::FakeRoleRepository;
use test_support::user_role::FakeUserRoleRepository;

use super::{ListUserRolesQuery, ListUserRolesQueryHandler, MAX_PAGE_SIZE, UserRolePage};
use crate::error::IamError;

const SUBJECT: &str = "0190f2a8-7b3c-7d4e-8f12-000000000001";
const PROJECT: &str = "0190f2a8-7b3c-7d4e-8f13-000000000001";

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(1_000))
        .unwrap()
}

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
        subject: SubjectRef::user(Uuid::parse(SUBJECT).unwrap()),
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

fn numbered(count: u32) -> Vec<UserRoleParts> {
    (1..=count).map(|number| parts(number, 1)).collect()
}

fn handler(user_roles: Vec<UserRoleParts>) -> ListUserRolesQueryHandler {
    handler_over(
        FakeUserRoleRepository::holding(user_roles),
        FakeRoleRepository::holding(vec![role(1), role(2)]),
    )
}

fn handler_over(
    user_roles: FakeUserRoleRepository,
    roles: FakeRoleRepository,
) -> ListUserRolesQueryHandler {
    let user_roles: Arc<dyn UserRoleRepository> = Arc::new(user_roles);
    let roles: Arc<dyn RoleRepository> = Arc::new(roles);
    ListUserRolesQueryHandler::new(user_roles, roles, Arc::new(FixedClock::at(now())))
}

fn query(limit: u32) -> ListUserRolesQuery {
    ListUserRolesQuery {
        limit,
        after: None,
        subject_kind: None,
        subject_id: None,
        role_id: None,
        project_id: None,
        include_expired: false,
    }
}

fn ids(page: &UserRolePage) -> Vec<UserRoleId> {
    page.user_roles
        .iter()
        .map(|view| view.user_role.id)
        .collect()
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(ListUserRolesQuery::NAME, "ListUserRolesQuery");
}

#[tokio::test]
async fn a_page_smaller_than_the_stock_names_the_last_assignment_as_its_cursor() {
    let handler = handler(numbered(5));

    let page = handler.handle(query(2)).await.unwrap();

    assert_eq!(ids(&page), [id(1), id(2)]);
    assert_eq!(page.next_after, Some(id(2)));
}

#[tokio::test]
async fn following_the_cursors_visits_every_assignment_exactly_once() {
    let handler = handler(numbered(5));
    let mut seen = Vec::new();
    let mut after = None;

    loop {
        let page = handler
            .handle(ListUserRolesQuery { after, ..query(2) })
            .await
            .unwrap();
        seen.extend(ids(&page));
        after = page.next_after;
        if after.is_none() {
            break;
        }
    }

    assert_eq!(seen, [id(1), id(2), id(3), id(4), id(5)]);
}

#[tokio::test]
async fn a_page_that_ends_the_stock_has_no_cursor() {
    let handler = handler(numbered(2));

    let page = handler.handle(query(2)).await.unwrap();

    assert_eq!(ids(&page), [id(1), id(2)]);
    assert_eq!(page.next_after, None);
}

#[tokio::test]
async fn no_assignment_is_an_empty_page() {
    let page = handler(Vec::new()).handle(query(10)).await.unwrap();

    assert_eq!(page.user_roles.len(), 0);
    assert_eq!(page.next_after, None);
}

#[tokio::test]
async fn a_limit_outside_the_range_is_brought_into_it() {
    let handler = handler(numbered(105));

    let zero = handler.handle(query(0)).await.unwrap();
    let huge = handler.handle(query(5_000)).await.unwrap();

    assert_eq!(zero.user_roles.len(), 1);
    assert_eq!(
        huge.user_roles.len(),
        usize::try_from(MAX_PAGE_SIZE).unwrap()
    );
    assert_eq!(huge.next_after, Some(id(MAX_PAGE_SIZE)));
}

#[tokio::test]
async fn each_assignment_carries_the_name_of_its_role() {
    let handler = handler(vec![parts(1, 1), parts(2, 2), parts(3, 1), parts(4, 9)]);

    let page = handler.handle(query(10)).await.unwrap();

    let names: Vec<Option<&str>> = page
        .user_roles
        .iter()
        .map(|view| view.role_name.as_ref().map(RoleName::as_str))
        .collect();
    assert_eq!(
        names,
        [Some("Role 1"), Some("Role 2"), Some("Role 1"), None]
    );
}

#[tokio::test]
async fn the_filters_select_by_subject_role_and_project() {
    let project = ProjectId::parse(PROJECT).unwrap();
    let service = UserRoleParts {
        subject: SubjectRef::service(ServiceName::new("billing-worker").unwrap()),
        ..parts(2, 1)
    };
    let scoped = UserRoleParts {
        scope: AssignmentScope::Project(project),
        ..parts(3, 2)
    };
    let handler = handler(vec![parts(1, 1), service, scoped]);

    let by_kind = handler
        .handle(ListUserRolesQuery {
            subject_kind: Some(SubjectKind::Service),
            ..query(10)
        })
        .await
        .unwrap();
    let by_subject = handler
        .handle(ListUserRolesQuery {
            subject_id: Some(SUBJECT.to_owned()),
            ..query(10)
        })
        .await
        .unwrap();
    let by_role = handler
        .handle(ListUserRolesQuery {
            role_id: Some(role_id(2)),
            ..query(10)
        })
        .await
        .unwrap();
    let by_project = handler
        .handle(ListUserRolesQuery {
            project_id: Some(project),
            ..query(10)
        })
        .await
        .unwrap();

    assert_eq!(ids(&by_kind), [id(2)]);
    assert_eq!(ids(&by_subject), [id(1), id(3)]);
    assert_eq!(ids(&by_role), [id(3)]);
    assert_eq!(ids(&by_project), [id(3)]);
}

#[tokio::test]
async fn expired_assignments_are_listed_only_when_requested_and_revoked_ones_never() {
    let expired = UserRoleParts {
        expires_at: Some(AssignmentExpiry::restore(
            SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(10))
                .unwrap(),
        )),
        ..parts(2, 1)
    };
    let revoked = UserRoleParts {
        revoked_at: Some(SystemTime::UNIX_EPOCH),
        ..parts(3, 1)
    };
    let handler = handler(vec![parts(1, 1), expired, revoked]);

    let active = handler.handle(query(10)).await.unwrap();
    let all = handler
        .handle(ListUserRolesQuery {
            include_expired: true,
            ..query(10)
        })
        .await
        .unwrap();

    assert_eq!(ids(&active), [id(1)]);
    assert_eq!(ids(&all), [id(1), id(2)]);
}

#[tokio::test]
async fn an_unreadable_assignment_store_is_a_storage_failure() {
    let handler = handler_over(FakeUserRoleRepository::failing(), FakeRoleRepository::new());

    let error = handler.handle(query(10)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)), "{error:?}");
}

#[tokio::test]
async fn an_unreadable_role_store_is_a_storage_failure() {
    let handler = handler_over(
        FakeUserRoleRepository::holding(numbered(1)),
        FakeRoleRepository::failing(),
    );

    let error = handler.handle(query(10)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)), "{error:?}");
}
