use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, ContentHash, EntityVersion, GqlName, GraphQlCoordinate, GraphQlField,
    GraphQlPermission, GraphQlSpec, GraphQlSpecContent, GraphQlSpecParts, GraphQlSpecStatement,
    GraphQlTypeGraph, PermissionFlags, PermissionGrant, PermissionGrantSet, PermissionId,
    PermissionKey, RoleId, RoleKind, RoleParts, ServiceName, SpecId, SpecStatus,
};
use shared_domain::{Query as _, QueryHandler as _, Uuid};
use test_support::graphql_permission::FakeGraphQlPermissionRepository;
use test_support::graphql_spec::FakeGraphQlSpecRepository;
use test_support::role::FakeRoleRepository;

use super::{
    GetGraphQlPermissionsQuery, GetGraphQlPermissionsQueryHandler, GraphQlPermissionView,
    MAX_PAGE_SIZE, PermissionReads,
};
use crate::error::IamError;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";

fn spec_id(number: u8) -> SpecId {
    SpecId::parse(&format!("0190f2a8-7b3c-7d4e-8f10-1234567890{number:02x}")).unwrap()
}

fn role_id(number: u8) -> RoleId {
    RoleId::parse(&format!("0190f2a8-7b3c-7d4e-8f11-1234567890{number:02x}")).unwrap()
}

fn permission_id(number: u8) -> PermissionId {
    PermissionId::parse(&format!("0190f2a8-7b3c-7d4e-8f12-1234567890{number:02x}")).unwrap()
}

fn billing() -> ServiceName {
    ServiceName::new("billing").unwrap()
}

fn entry(number: u8, key: &str, flags: PermissionFlags) -> GraphQlPermission {
    GraphQlPermission::create(
        permission_id(number),
        PermissionKey::parse(key).unwrap(),
        flags,
    )
    .unwrap()
}

fn spec(number: u8, service: &str, status: SpecStatus, fields: &[&str]) -> GraphQlSpecStatement {
    let at = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap();
    let graph = GraphQlTypeGraph::new(
        fields.iter().map(|text| {
            (
                GraphQlCoordinate::parse(text).unwrap(),
                GraphQlField {
                    return_type: GqlName::parse("String").unwrap(),
                    flags: PermissionFlags::NONE,
                },
            )
        }),
        [],
    )
    .unwrap();
    let spec = GraphQlSpec::restore(GraphQlSpecParts {
        id: spec_id(number),
        content: GraphQlSpecContent {
            service: ServiceName::new(service).unwrap(),
            content_hash: ContentHash::new(&[number; 32]).unwrap(),
            type_graph: graph,
        },
        status,
        uploaded_by: ActorRef::User(Uuid::parse(USER).unwrap()),
        created_at: at,
        activated_at: (status != SpecStatus::Draft).then_some(at),
        retired_at: None,
    });
    GraphQlSpecStatement::insert(&spec, format!("sdl {number}"))
}

fn role(number: u8, grants: &[&str]) -> RoleParts {
    let at = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap();
    RoleParts {
        id: role_id(number),
        name: iam_domain::RoleName::new(format!("Role {number}")).unwrap(),
        description: None,
        kind: RoleKind::Custom,
        grants: PermissionGrantSet::new(
            grants
                .iter()
                .map(|grant| PermissionGrant::parse(grant).unwrap()),
        )
        .unwrap(),
        version: EntityVersion::INITIAL,
        created_at: at,
        updated_at: at,
        deleted_at: None,
    }
}

fn reads(
    entries: &[GraphQlPermission],
    specs: &[GraphQlSpecStatement],
    roles: Vec<RoleParts>,
) -> PermissionReads {
    let permissions = FakeGraphQlPermissionRepository::new();
    for stored in entries {
        permissions.insert(stored).unwrap();
    }
    let spec_repository = FakeGraphQlSpecRepository::new();
    for statement in specs {
        spec_repository.save(statement).unwrap();
    }
    PermissionReads {
        permissions: Arc::new(permissions),
        specs: Arc::new(spec_repository),
        roles: Arc::new(FakeRoleRepository::holding(roles)),
    }
}

fn numbered(count: u8) -> Vec<GraphQlPermission> {
    (1..=count)
        .map(|number| {
            entry(
                number,
                &format!("gql:billing:Query.field{number}"),
                PermissionFlags::NONE,
            )
        })
        .collect()
}

fn query(limit: u32) -> GetGraphQlPermissionsQuery {
    GetGraphQlPermissionsQuery {
        limit,
        after: None,
        service: None,
        type_name: None,
        active: None,
        sensitive: None,
        key_prefix: None,
    }
}

fn ids(page: &super::GraphQlPermissionPage) -> Vec<PermissionId> {
    page.permissions
        .iter()
        .map(|view| view.permission.id)
        .collect()
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(
        GetGraphQlPermissionsQuery::NAME,
        "GetGraphQlPermissionsQuery"
    );
}

#[test]
fn the_largest_page_holds_a_hundred_entries() {
    assert_eq!(MAX_PAGE_SIZE, 100);
}

#[tokio::test]
async fn a_page_smaller_than_the_stock_names_the_last_entry_as_its_cursor() {
    let handler = GetGraphQlPermissionsQueryHandler::new(reads(&numbered(5), &[], Vec::new()));

    let page = handler.handle(query(2)).await.unwrap();

    assert_eq!(ids(&page), [permission_id(1), permission_id(2)]);
    assert_eq!(page.next_after, Some(permission_id(2)));
}

#[tokio::test]
async fn following_the_cursors_visits_every_entry_exactly_once() {
    let handler = GetGraphQlPermissionsQueryHandler::new(reads(&numbered(5), &[], Vec::new()));
    let mut seen = Vec::new();
    let mut after = None;

    loop {
        let page = handler
            .handle(GetGraphQlPermissionsQuery { after, ..query(2) })
            .await
            .unwrap();
        seen.extend(ids(&page));
        after = page.next_after;
        if after.is_none() {
            break;
        }
    }

    assert_eq!(seen, (1..=5).map(permission_id).collect::<Vec<_>>());
}

#[tokio::test]
async fn the_last_page_has_no_cursor() {
    let handler = GetGraphQlPermissionsQueryHandler::new(reads(&numbered(2), &[], Vec::new()));

    let page = handler.handle(query(2)).await.unwrap();

    assert_eq!(ids(&page), [permission_id(1), permission_id(2)]);
    assert_eq!(page.next_after, None);
}

#[tokio::test]
async fn a_limit_of_zero_is_a_page_of_one_and_a_huge_limit_is_the_largest_page() {
    let handler = GetGraphQlPermissionsQueryHandler::new(reads(&numbered(3), &[], Vec::new()));

    let one = handler.handle(query(0)).await.unwrap();
    let all = handler.handle(query(u32::MAX)).await.unwrap();

    assert_eq!(ids(&one), [permission_id(1)]);
    assert_eq!(all.permissions.len(), 3);
    assert_eq!(all.next_after, None);
}

#[tokio::test]
async fn the_filters_reach_the_repository() {
    let mut sensitive = entry(
        4,
        "gql:billing:Mutation.pay",
        PermissionFlags::NONE.with_sensitive(),
    );
    sensitive.deactivate();
    let mut entries = numbered(3);
    entries.push(sensitive);
    entries.push(entry(
        5,
        "gql:shipping:Query.parcels",
        PermissionFlags::NONE,
    ));
    let handler = GetGraphQlPermissionsQueryHandler::new(reads(&entries, &[], Vec::new()));

    let by_service = handler
        .handle(GetGraphQlPermissionsQuery {
            service: Some(ServiceName::new("shipping").unwrap()),
            ..query(10)
        })
        .await
        .unwrap();
    let by_type = handler
        .handle(GetGraphQlPermissionsQuery {
            type_name: Some(GqlName::parse("Mutation").unwrap()),
            ..query(10)
        })
        .await
        .unwrap();
    let inactive = handler
        .handle(GetGraphQlPermissionsQuery {
            active: Some(false),
            ..query(10)
        })
        .await
        .unwrap();
    let sensitive_only = handler
        .handle(GetGraphQlPermissionsQuery {
            sensitive: Some(true),
            ..query(10)
        })
        .await
        .unwrap();
    let prefixed = handler
        .handle(GetGraphQlPermissionsQuery {
            key_prefix: Some("gql:billing:Query.field".to_owned()),
            ..query(10)
        })
        .await
        .unwrap();

    assert_eq!(ids(&by_service), [permission_id(5)]);
    assert_eq!(ids(&by_type), [permission_id(4)]);
    assert_eq!(ids(&inactive), [permission_id(4)]);
    assert_eq!(ids(&sensitive_only), [permission_id(4)]);
    assert_eq!(ids(&prefixed).len(), 3);
}

#[tokio::test]
async fn an_entry_lists_the_active_versions_that_contain_its_key_and_the_roles_that_grant_it() {
    let entries = [
        entry(1, "gql:billing:Query.invoices", PermissionFlags::NONE),
        entry(2, "gql:billing:Query.orders", PermissionFlags::NONE),
    ];
    let specs = [
        spec(
            2,
            "billing",
            SpecStatus::Active,
            &["Query.invoices", "Query.orders"],
        ),
        spec(1, "billing", SpecStatus::Active, &["Query.invoices"]),
        spec(3, "billing", SpecStatus::Draft, &["Query.invoices"]),
        spec(4, "billing", SpecStatus::Retired, &["Query.invoices"]),
    ];
    let roles = vec![
        role(2, &["gql:billing:Query.invoices"]),
        role(
            1,
            &["gql:billing:Query.invoices", "gql:billing:Query.orders"],
        ),
        role(3, &["gql:billing:Query.*"]),
    ];
    let handler = GetGraphQlPermissionsQueryHandler::new(reads(&entries, &specs, roles));

    let page = handler.handle(query(10)).await.unwrap();

    let [invoices, orders] = page.permissions.as_slice() else {
        panic!("two entries expected");
    };
    assert_eq!(invoices.versions, [spec_id(1), spec_id(2)]);
    assert_eq!(invoices.roles, [role_id(1), role_id(2)]);
    assert_eq!(orders.versions, [spec_id(2)]);
    assert_eq!(orders.roles, [role_id(1)]);
}

#[tokio::test]
async fn the_introspection_key_is_in_every_active_version_of_its_service_only() {
    let entries = [entry(
        1,
        "gql:billing:__introspection",
        PermissionFlags::NONE,
    )];
    let specs = [
        spec(1, "billing", SpecStatus::Active, &["Query.invoices"]),
        spec(2, "billing", SpecStatus::Draft, &["Query.invoices"]),
        spec(3, "shipping", SpecStatus::Active, &["Query.parcels"]),
    ];
    let handler = GetGraphQlPermissionsQueryHandler::new(reads(&entries, &specs, Vec::new()));

    let page = handler.handle(query(10)).await.unwrap();

    let [introspection] = page.permissions.as_slice() else {
        panic!("one entry expected");
    };
    assert_eq!(introspection.versions, [spec_id(1)]);
    assert_eq!(introspection.roles, Vec::<RoleId>::new());
    assert_eq!(introspection.permission.key.service(), &billing());
}

#[tokio::test]
async fn an_entry_without_a_holding_version_or_role_lists_none() {
    let entries = [entry(1, "gql:billing:Query.gone", PermissionFlags::NONE)];
    let specs = [spec(1, "billing", SpecStatus::Active, &["Query.invoices"])];
    let handler = GetGraphQlPermissionsQueryHandler::new(reads(&entries, &specs, Vec::new()));

    let page = handler.handle(query(10)).await.unwrap();

    assert_eq!(page.permissions[0].versions, Vec::<SpecId>::new());
    assert_eq!(page.permissions[0].roles, Vec::<RoleId>::new());
}

#[tokio::test]
async fn an_empty_catalogue_is_an_empty_page() {
    let handler = GetGraphQlPermissionsQueryHandler::new(reads(&[], &[], Vec::new()));

    let page = handler.handle(query(10)).await.unwrap();

    assert_eq!(page.permissions, Vec::<GraphQlPermissionView>::new());
    assert_eq!(page.next_after, None);
}

#[tokio::test]
async fn a_failing_catalogue_is_a_storage_error() {
    let mut failing = reads(&[], &[], Vec::new());
    failing.permissions = Arc::new(FakeGraphQlPermissionRepository::failing());
    let handler = GetGraphQlPermissionsQueryHandler::new(failing);

    let error = handler.handle(query(10)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}

#[tokio::test]
async fn failing_versions_are_a_storage_error() {
    let mut failing = reads(&numbered(1), &[], Vec::new());
    failing.specs = Arc::new(FakeGraphQlSpecRepository::failing());
    let handler = GetGraphQlPermissionsQueryHandler::new(failing);

    let error = handler.handle(query(10)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}

#[tokio::test]
async fn failing_roles_are_a_storage_error() {
    let mut failing = reads(&numbered(1), &[], Vec::new());
    failing.roles = Arc::new(FakeRoleRepository::failing());
    let handler = GetGraphQlPermissionsQueryHandler::new(failing);

    let error = handler.handle(query(10)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
