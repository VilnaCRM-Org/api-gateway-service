use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    EntityVersion, PermissionGrantSet, RoleId, RoleKind, RoleName, RoleParts, RoleRepository,
};
use shared_domain::{Query as _, QueryHandler as _};
use test_support::role::FakeRoleRepository;

use super::{ListRolesQuery, ListRolesQueryHandler, MAX_PAGE_SIZE, RolePage};
use crate::error::IamError;

fn id(number: u32) -> RoleId {
    RoleId::parse(&format!("0190f2a8-7b3c-7d4e-8f10-{number:012x}")).unwrap()
}

fn parts(number: u32, name: &str, kind: RoleKind) -> RoleParts {
    RoleParts {
        id: id(number),
        name: RoleName::new(name.to_owned()).unwrap(),
        description: None,
        kind,
        grants: PermissionGrantSet::default(),
        version: EntityVersion::INITIAL,
        created_at: SystemTime::UNIX_EPOCH,
        updated_at: SystemTime::UNIX_EPOCH,
        deleted_at: None,
    }
}

fn numbered(count: u32) -> Vec<RoleParts> {
    (1..=count)
        .map(|number| parts(number, &format!("Role {number}"), RoleKind::Custom))
        .collect()
}

fn handler(roles: Vec<RoleParts>) -> ListRolesQueryHandler {
    let roles: Arc<dyn RoleRepository> = Arc::new(FakeRoleRepository::holding(roles));
    ListRolesQueryHandler::new(roles)
}

fn query(limit: u32) -> ListRolesQuery {
    ListRolesQuery {
        limit,
        after: None,
        name_prefix: None,
        kind: None,
    }
}

fn ids(page: &RolePage) -> Vec<RoleId> {
    page.roles.iter().map(|role| role.id).collect()
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(ListRolesQuery::NAME, "ListRolesQuery");
}

#[tokio::test]
async fn a_page_smaller_than_the_stock_names_the_last_role_as_its_cursor() {
    let handler = handler(numbered(5));

    let page = handler.handle(query(2)).await.unwrap();

    assert_eq!(ids(&page), [id(1), id(2)]);
    assert_eq!(page.next_after, Some(id(2)));
}

#[tokio::test]
async fn following_the_cursors_visits_every_role_exactly_once() {
    let handler = handler(numbered(5));
    let mut seen = Vec::new();
    let mut after = None;

    loop {
        let page = handler
            .handle(ListRolesQuery { after, ..query(2) })
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
    let handler = handler(numbered(4));

    let page = handler
        .handle(ListRolesQuery {
            after: Some(id(2)),
            ..query(2)
        })
        .await
        .unwrap();

    assert_eq!(ids(&page), [id(3), id(4)]);
    assert_eq!(page.next_after, None);
}

#[tokio::test]
async fn a_stock_smaller_than_the_page_has_no_cursor() {
    let handler = handler(numbered(3));

    let page = handler.handle(query(10)).await.unwrap();

    assert_eq!(page.roles.len(), 3);
    assert_eq!(page.next_after, None);
}

#[tokio::test]
async fn no_role_is_an_empty_page_without_a_cursor() {
    let handler = handler(Vec::new());

    let page = handler.handle(query(10)).await.unwrap();

    assert_eq!(
        page,
        RolePage {
            roles: Vec::new(),
            next_after: None
        }
    );
}

#[tokio::test]
async fn a_limit_of_zero_is_brought_up_to_one() {
    let handler = handler(numbered(3));

    let page = handler.handle(query(0)).await.unwrap();

    assert_eq!(ids(&page), [id(1)]);
    assert_eq!(page.next_after, Some(id(1)));
}

#[tokio::test]
async fn a_limit_above_the_maximum_is_brought_down_to_it() {
    let handler = handler(numbered(MAX_PAGE_SIZE + 2));

    let page = handler.handle(query(MAX_PAGE_SIZE + 1)).await.unwrap();

    assert_eq!(page.roles.len(), 100);
    assert_eq!(page.next_after, Some(id(100)));
}

#[tokio::test]
async fn the_name_prefix_and_the_kind_filter_the_roles() {
    let handler = handler(vec![
        parts(1, "Billing admin", RoleKind::Custom),
        parts(2, "billing reader", RoleKind::Custom),
        parts(3, "Billing system", RoleKind::System),
        parts(4, "Support", RoleKind::Custom),
    ]);

    let by_prefix = handler
        .handle(ListRolesQuery {
            name_prefix: Some("BILL".to_owned()),
            ..query(10)
        })
        .await
        .unwrap();
    let by_kind = handler
        .handle(ListRolesQuery {
            kind: Some(RoleKind::System),
            ..query(10)
        })
        .await
        .unwrap();

    assert_eq!(ids(&by_prefix), [id(1), id(2), id(3)]);
    assert_eq!(ids(&by_kind), [id(3)]);
}

#[tokio::test]
async fn a_failing_repository_is_a_storage_failure() {
    let roles: Arc<dyn RoleRepository> = Arc::new(FakeRoleRepository::failing());
    let handler = ListRolesQueryHandler::new(roles);

    let error = handler.handle(query(10)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)), "{error:?}");
}
