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

use super::{GetRestPermissionQuery, GetRestPermissionQueryHandler};
use crate::error::IamError;
use crate::query::get_rest_permissions::RestPermissionReads;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const KEY: &str = "rest:billing:GET /api/invoices/{}";

fn permission_id(number: u8) -> PermissionId {
    PermissionId::parse(&format!("0190f2a8-7b3c-7d4e-8f12-1234567890{number:02x}")).unwrap()
}

fn spec_id() -> SpecId {
    SpecId::parse("0190f2a8-7b3c-7d4e-8f10-1234567890c1").unwrap()
}

fn role_id() -> RoleId {
    RoleId::parse("0190f2a8-7b3c-7d4e-8f11-1234567890c2").unwrap()
}

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn active_spec() -> OpenApiSpecStatement {
    let mut operations = RestOperationSet::new();
    operations
        .insert(RestOperation {
            method: HttpMethod::Get,
            template: PathTemplate::from_openapi_path("/api/invoices/{id}").unwrap(),
            label: None,
            flags: PermissionFlags::NONE,
        })
        .unwrap();
    let spec = OpenApiSpec::restore(OpenApiSpecParts {
        id: spec_id(),
        content: OpenApiSpecContent {
            service: ServiceName::new("billing").unwrap(),
            content_hash: ContentHash::new(&[1; 32]).unwrap(),
            operations,
        },
        status: SpecStatus::Active,
        uploaded_by: ActorRef::User(Uuid::parse(USER).unwrap()),
        created_at: at(),
        activated_at: Some(at()),
        retired_at: None,
    });
    OpenApiSpecStatement::insert(&spec, "document".to_owned())
}

fn granting_role() -> RoleParts {
    RoleParts {
        id: role_id(),
        name: iam_domain::RoleName::new("Biller".to_owned()).unwrap(),
        description: None,
        kind: RoleKind::Custom,
        grants: PermissionGrantSet::new([PermissionGrant::parse(KEY).unwrap()]).unwrap(),
        version: EntityVersion::INITIAL,
        created_at: at(),
        updated_at: at(),
        deleted_at: None,
    }
}

fn handler() -> GetRestPermissionQueryHandler {
    let permissions = FakeRestPermissionRepository::new();
    permissions
        .insert(
            &RestPermission::create(
                permission_id(1),
                PermissionKey::parse(KEY).unwrap(),
                PermissionFlags::NONE.with_audit_always(),
            )
            .unwrap(),
        )
        .unwrap();
    let specs = FakeOpenApiSpecRepository::new();
    specs.save(&active_spec()).unwrap();
    GetRestPermissionQueryHandler::new(RestPermissionReads {
        permissions: Arc::new(permissions),
        specs: Arc::new(specs),
        roles: Arc::new(FakeRoleRepository::holding(vec![granting_role()])),
    })
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(GetRestPermissionQuery::NAME, "GetRestPermissionQuery");
}

#[tokio::test]
async fn a_known_entry_carries_its_versions_and_roles() {
    let view = handler()
        .handle(GetRestPermissionQuery {
            id: permission_id(1),
        })
        .await
        .unwrap()
        .unwrap();

    assert_eq!(view.permission.id, permission_id(1));
    assert!(view.permission.flags.is_audit_always());
    assert_eq!(view.versions, [spec_id()]);
    assert_eq!(view.roles, [role_id()]);
}

#[tokio::test]
async fn an_unknown_entry_is_none() {
    let view = handler()
        .handle(GetRestPermissionQuery {
            id: permission_id(9),
        })
        .await
        .unwrap();

    assert_eq!(view, None);
}

#[tokio::test]
async fn a_failing_catalogue_is_a_storage_error() {
    let failing = GetRestPermissionQueryHandler::new(RestPermissionReads {
        permissions: Arc::new(FakeRestPermissionRepository::failing()),
        specs: Arc::new(FakeOpenApiSpecRepository::new()),
        roles: Arc::new(FakeRoleRepository::new()),
    });

    let error = failing
        .handle(GetRestPermissionQuery {
            id: permission_id(1),
        })
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
