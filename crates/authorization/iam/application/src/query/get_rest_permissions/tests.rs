use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, ContentHash, EntityVersion, HttpMethod, OpenApiSpec, OpenApiSpecContent,
    OpenApiSpecParts, OpenApiSpecStatement, PathTemplate, PermissionFlags, PermissionGrant,
    PermissionGrantSet, PermissionId, PermissionKey, RestOperation, RestOperationSet,
    RestPermission, RoleId, RoleKind, RoleParts, ServiceName, SpecId, SpecStatus,
};
use shared_domain::{Query as _, QueryHandler as _, Uuid};
use test_support::openapi_spec::FakeOpenApiSpecRepository;
use test_support::rest_permission::FakeRestPermissionRepository;
use test_support::role::FakeRoleRepository;

use super::{
    GetRestPermissionsQuery, GetRestPermissionsQueryHandler, MAX_PAGE_SIZE, RestPermissionPage,
    RestPermissionReads, RestPermissionView,
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

fn entry(number: u8, key: &str, flags: PermissionFlags) -> RestPermission {
    RestPermission::create(
        permission_id(number),
        PermissionKey::parse(key).unwrap(),
        flags,
    )
    .unwrap()
}

fn spec(
    number: u8,
    service: &str,
    status: SpecStatus,
    operations: &[(HttpMethod, &str)],
) -> OpenApiSpecStatement {
    let at = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap();
    let mut set = RestOperationSet::new();
    for (method, path) in operations {
        set.insert(RestOperation {
            method: *method,
            template: PathTemplate::from_openapi_path(path).unwrap(),
            label: None,
            flags: PermissionFlags::NONE,
        })
        .unwrap();
    }
    let spec = OpenApiSpec::restore(OpenApiSpecParts {
        id: spec_id(number),
        content: OpenApiSpecContent {
            service: ServiceName::new(service).unwrap(),
            content_hash: ContentHash::new(&[number; 32]).unwrap(),
            operations: set,
        },
        status,
        uploaded_by: ActorRef::User(Uuid::parse(USER).unwrap()),
        created_at: at,
        activated_at: (status != SpecStatus::Draft).then_some(at),
        retired_at: None,
    });
    OpenApiSpecStatement::insert(&spec, format!("document {number}"))
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
    entries: &[RestPermission],
    specs: &[OpenApiSpecStatement],
    roles: Vec<RoleParts>,
) -> RestPermissionReads {
    let permissions = FakeRestPermissionRepository::new();
    for stored in entries {
        permissions.insert(stored).unwrap();
    }
    let spec_repository = FakeOpenApiSpecRepository::new();
    for statement in specs {
        spec_repository.save(statement).unwrap();
    }
    RestPermissionReads {
        permissions: Arc::new(permissions),
        specs: Arc::new(spec_repository),
        roles: Arc::new(FakeRoleRepository::holding(roles)),
    }
}

fn numbered(count: u8) -> Vec<RestPermission> {
    (1..=count)
        .map(|number| {
            entry(
                number,
                &format!("rest:billing:GET /api/items{number}"),
                PermissionFlags::NONE,
            )
        })
        .collect()
}

fn query(limit: u32) -> GetRestPermissionsQuery {
    GetRestPermissionsQuery {
        limit,
        after: None,
        service: None,
        method: None,
        active: None,
        sensitive: None,
        template_prefix: None,
    }
}

fn ids(page: &RestPermissionPage) -> Vec<PermissionId> {
    page.permissions
        .iter()
        .map(|view| view.permission.id)
        .collect()
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(GetRestPermissionsQuery::NAME, "GetRestPermissionsQuery");
}

#[test]
fn the_largest_page_is_that_of_the_graphql_catalogue() {
    assert_eq!(MAX_PAGE_SIZE, 100);
}

#[tokio::test]
async fn a_page_smaller_than_the_stock_names_the_last_entry_as_its_cursor() {
    let handler = GetRestPermissionsQueryHandler::new(reads(&numbered(5), &[], Vec::new()));

    let page = handler.handle(query(2)).await.unwrap();

    assert_eq!(ids(&page), [permission_id(1), permission_id(2)]);
    assert_eq!(page.next_after, Some(permission_id(2)));
}

#[tokio::test]
async fn following_the_cursors_visits_every_entry_exactly_once() {
    let handler = GetRestPermissionsQueryHandler::new(reads(&numbered(5), &[], Vec::new()));
    let mut seen = Vec::new();
    let mut after = None;

    loop {
        let page = handler
            .handle(GetRestPermissionsQuery { after, ..query(2) })
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
    let handler = GetRestPermissionsQueryHandler::new(reads(&numbered(2), &[], Vec::new()));

    let page = handler.handle(query(2)).await.unwrap();

    assert_eq!(ids(&page), [permission_id(1), permission_id(2)]);
    assert_eq!(page.next_after, None);
}

#[tokio::test]
async fn a_limit_of_zero_is_a_page_of_one_and_a_huge_limit_is_the_largest_page() {
    let handler = GetRestPermissionsQueryHandler::new(reads(&numbered(3), &[], Vec::new()));

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
        "rest:billing:POST /api/pay",
        PermissionFlags::NONE.with_sensitive(),
    );
    sensitive.deactivate();
    let mut entries = numbered(3);
    entries.push(sensitive);
    entries.push(entry(
        5,
        "rest:shipping:GET /api/parcels",
        PermissionFlags::NONE,
    ));
    let handler = GetRestPermissionsQueryHandler::new(reads(&entries, &[], Vec::new()));

    let by_service = handler
        .handle(GetRestPermissionsQuery {
            service: Some(ServiceName::new("shipping").unwrap()),
            ..query(10)
        })
        .await
        .unwrap();
    let by_method = handler
        .handle(GetRestPermissionsQuery {
            method: Some(HttpMethod::Post),
            ..query(10)
        })
        .await
        .unwrap();
    let inactive = handler
        .handle(GetRestPermissionsQuery {
            active: Some(false),
            ..query(10)
        })
        .await
        .unwrap();
    let sensitive_only = handler
        .handle(GetRestPermissionsQuery {
            sensitive: Some(true),
            ..query(10)
        })
        .await
        .unwrap();

    assert_eq!(ids(&by_service), [permission_id(5)]);
    assert_eq!(ids(&by_method), [permission_id(4)]);
    assert_eq!(ids(&inactive), [permission_id(4)]);
    assert_eq!(ids(&sensitive_only), [permission_id(4)]);
}

#[tokio::test]
async fn the_template_prefix_keeps_the_entries_whose_template_starts_with_it() {
    let entries = [
        entry(1, "rest:billing:GET /api/invoices", PermissionFlags::NONE),
        entry(2, "rest:billing:GET /api/orders", PermissionFlags::NONE),
        entry(
            3,
            "rest:billing:POST /api/invoices/{}/pay",
            PermissionFlags::NONE,
        ),
        entry(4, "rest:shipping:GET /api/invoices", PermissionFlags::NONE),
    ];
    let handler = GetRestPermissionsQueryHandler::new(reads(&entries, &[], Vec::new()));

    let invoices = handler
        .handle(GetRestPermissionsQuery {
            template_prefix: Some("/api/invoices".to_owned()),
            ..query(10)
        })
        .await
        .unwrap();
    let billing_invoices = handler
        .handle(GetRestPermissionsQuery {
            template_prefix: Some("/api/invoices".to_owned()),
            service: Some(ServiceName::new("billing").unwrap()),
            method: Some(HttpMethod::Get),
            ..query(10)
        })
        .await
        .unwrap();
    let nothing = handler
        .handle(GetRestPermissionsQuery {
            template_prefix: Some("/other".to_owned()),
            ..query(10)
        })
        .await
        .unwrap();

    assert_eq!(
        ids(&invoices),
        [permission_id(1), permission_id(3), permission_id(4)]
    );
    assert_eq!(ids(&billing_invoices), [permission_id(1)]);
    assert_eq!(nothing.permissions, Vec::<RestPermissionView>::new());
    assert_eq!(nothing.next_after, None);
}

#[tokio::test]
async fn pages_of_a_template_prefix_follow_the_cursors_over_the_whole_catalogue() {
    let mut entries: Vec<RestPermission> = (1..=120)
        .map(|number| {
            entry(
                number,
                &format!("rest:billing:GET /api/noise{number}"),
                PermissionFlags::NONE,
            )
        })
        .collect();
    entries.push(entry(
        121,
        "rest:billing:GET /api/hit/a",
        PermissionFlags::NONE,
    ));
    entries.push(entry(
        122,
        "rest:billing:GET /api/hit/b",
        PermissionFlags::NONE,
    ));
    entries.push(entry(
        123,
        "rest:billing:GET /api/hit/c",
        PermissionFlags::NONE,
    ));
    let handler = GetRestPermissionsQueryHandler::new(reads(&entries, &[], Vec::new()));
    let mut seen = Vec::new();
    let mut after = None;

    loop {
        let page = handler
            .handle(GetRestPermissionsQuery {
                after,
                template_prefix: Some("/api/hit".to_owned()),
                ..query(2)
            })
            .await
            .unwrap();
        seen.extend(ids(&page));
        after = page.next_after;
        if after.is_none() {
            break;
        }
    }

    assert_eq!(
        seen,
        [permission_id(121), permission_id(122), permission_id(123)]
    );
}

#[tokio::test]
async fn an_entry_lists_the_active_versions_that_contain_its_key_and_the_roles_that_grant_it() {
    let entries = [
        entry(1, "rest:billing:GET /api/invoices", PermissionFlags::NONE),
        entry(
            2,
            "rest:billing:POST /api/invoices/{}/pay",
            PermissionFlags::NONE,
        ),
    ];
    let specs = [
        spec(
            2,
            "billing",
            SpecStatus::Active,
            &[
                (HttpMethod::Get, "/api/invoices"),
                (HttpMethod::Post, "/api/invoices/{id}/pay"),
            ],
        ),
        spec(
            1,
            "billing",
            SpecStatus::Active,
            &[(HttpMethod::Get, "/api/invoices")],
        ),
        spec(
            3,
            "billing",
            SpecStatus::Draft,
            &[(HttpMethod::Get, "/api/invoices")],
        ),
        spec(
            4,
            "billing",
            SpecStatus::Retired,
            &[(HttpMethod::Get, "/api/invoices")],
        ),
        spec(
            5,
            "shipping",
            SpecStatus::Active,
            &[(HttpMethod::Get, "/api/invoices")],
        ),
    ];
    let roles = vec![
        role(2, &["rest:billing:GET /api/invoices"]),
        role(
            1,
            &[
                "rest:billing:GET /api/invoices",
                "rest:billing:POST /api/invoices/{}/pay",
            ],
        ),
        role(3, &["rest:billing:GET *"]),
    ];
    let handler = GetRestPermissionsQueryHandler::new(reads(&entries, &specs, roles));

    let page = handler.handle(query(10)).await.unwrap();

    let [invoices, pay] = page.permissions.as_slice() else {
        panic!("two entries expected");
    };
    assert_eq!(invoices.versions, [spec_id(1), spec_id(2)]);
    assert_eq!(invoices.roles, [role_id(1), role_id(2)]);
    assert_eq!(pay.versions, [spec_id(2)]);
    assert_eq!(pay.roles, [role_id(1)]);
}

#[tokio::test]
async fn an_entry_without_a_holding_version_or_role_lists_none() {
    let entries = [entry(
        1,
        "rest:billing:GET /api/gone",
        PermissionFlags::NONE,
    )];
    let specs = [spec(
        1,
        "billing",
        SpecStatus::Active,
        &[(HttpMethod::Get, "/api/invoices")],
    )];
    let handler = GetRestPermissionsQueryHandler::new(reads(&entries, &specs, Vec::new()));

    let page = handler.handle(query(10)).await.unwrap();

    assert_eq!(page.permissions[0].versions, Vec::<SpecId>::new());
    assert_eq!(page.permissions[0].roles, Vec::<RoleId>::new());
}

#[tokio::test]
async fn an_empty_catalogue_is_an_empty_page() {
    let handler = GetRestPermissionsQueryHandler::new(reads(&[], &[], Vec::new()));

    let page = handler.handle(query(10)).await.unwrap();

    assert_eq!(page.permissions, Vec::<RestPermissionView>::new());
    assert_eq!(page.next_after, None);
}

#[tokio::test]
async fn a_failing_catalogue_is_a_storage_error() {
    let mut failing = reads(&[], &[], Vec::new());
    failing.permissions = Arc::new(FakeRestPermissionRepository::failing());
    let handler = GetRestPermissionsQueryHandler::new(failing);

    let error = handler.handle(query(10)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}

#[tokio::test]
async fn a_failing_catalogue_is_a_storage_error_under_a_template_prefix() {
    let mut failing = reads(&[], &[], Vec::new());
    failing.permissions = Arc::new(FakeRestPermissionRepository::failing());
    let handler = GetRestPermissionsQueryHandler::new(failing);

    let error = handler
        .handle(GetRestPermissionsQuery {
            template_prefix: Some("/api".to_owned()),
            ..query(10)
        })
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}

#[tokio::test]
async fn failing_versions_are_a_storage_error() {
    let mut failing = reads(&numbered(1), &[], Vec::new());
    failing.specs = Arc::new(FakeOpenApiSpecRepository::failing());
    let handler = GetRestPermissionsQueryHandler::new(failing);

    let error = handler.handle(query(10)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}

#[tokio::test]
async fn failing_roles_are_a_storage_error() {
    let mut failing = reads(&numbered(1), &[], Vec::new());
    failing.roles = Arc::new(FakeRoleRepository::failing());
    let handler = GetRestPermissionsQueryHandler::new(failing);

    let error = handler.handle(query(10)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
