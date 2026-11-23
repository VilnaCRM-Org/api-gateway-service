use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, ContentHash, EntityVersion, HttpMethod, OpenApiSpec, OpenApiSpecContent,
    OpenApiSpecParts, OpenApiSpecStatement, PathTemplate, PermissionFlags, PermissionGrant,
    PermissionGrantSet, RestOperation, RestOperationSet, RoleId, RoleKind, RoleParts, ServiceName,
    SpecId, SpecStatus,
};
use shared_domain::{Query as _, QueryHandler as _, Uuid};
use test_support::openapi_spec::FakeOpenApiSpecRepository;
use test_support::role::FakeRoleRepository;

use super::{GetOpenApiSpecDiffQuery, GetOpenApiSpecDiffQueryHandler};
use crate::error::IamError;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";

fn service() -> ServiceName {
    ServiceName::new("billing").unwrap()
}

fn spec_id(number: u8) -> SpecId {
    SpecId::parse(&format!("0190f2a8-7b3c-7d4e-8f10-1234567890{number:02x}")).unwrap()
}

fn role_id(number: u8) -> RoleId {
    RoleId::parse(&format!("0190f2a8-7b3c-7d4e-8f11-1234567890{number:02x}")).unwrap()
}

fn operations(entries: &[(HttpMethod, &str, PermissionFlags)]) -> RestOperationSet {
    let mut set = RestOperationSet::new();
    for (method, path, flags) in entries {
        set.insert(RestOperation {
            method: *method,
            template: PathTemplate::from_openapi_path(path).unwrap(),
            label: None,
            flags: *flags,
        })
        .unwrap();
    }
    set
}

fn spec(
    number: u8,
    status: SpecStatus,
    entries: &[(HttpMethod, &str, PermissionFlags)],
) -> OpenApiSpecStatement {
    let at = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap();
    let spec = OpenApiSpec::restore(OpenApiSpecParts {
        id: spec_id(number),
        content: OpenApiSpecContent {
            service: service(),
            content_hash: ContentHash::new(&[number; 32]).unwrap(),
            operations: operations(entries),
        },
        status,
        uploaded_by: ActorRef::User(Uuid::parse(USER).unwrap()),
        created_at: at,
        activated_at: (status != SpecStatus::Draft).then_some(at),
        retired_at: None,
    });
    OpenApiSpecStatement::insert(&spec, format!("document {number}"))
}

fn repository(statements: &[OpenApiSpecStatement]) -> Arc<FakeOpenApiSpecRepository> {
    let repository = FakeOpenApiSpecRepository::new();
    for statement in statements {
        repository.save(statement).unwrap();
    }
    Arc::new(repository)
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

fn handler(
    specs: Arc<FakeOpenApiSpecRepository>,
    roles: FakeRoleRepository,
) -> GetOpenApiSpecDiffQueryHandler {
    GetOpenApiSpecDiffQueryHandler::new(specs, Arc::new(roles))
}

const NONE: PermissionFlags = PermissionFlags::NONE;

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(GetOpenApiSpecDiffQuery::NAME, "GetOpenApiSpecDiffQuery");
}

#[tokio::test]
async fn an_unknown_version_is_none() {
    let handler = handler(repository(&[]), FakeRoleRepository::new());

    let view = handler
        .handle(GetOpenApiSpecDiffQuery { id: spec_id(1) })
        .await
        .unwrap();

    assert_eq!(view, None);
}

#[tokio::test]
async fn the_first_version_of_a_service_adds_every_operation_and_removes_none() {
    let draft = spec(
        1,
        SpecStatus::Draft,
        &[
            (HttpMethod::Get, "/invoices", NONE),
            (HttpMethod::Post, "/invoices", NONE.with_sensitive()),
        ],
    );
    let handler = handler(repository(&[draft]), FakeRoleRepository::new());

    let view = handler
        .handle(GetOpenApiSpecDiffQuery { id: spec_id(1) })
        .await
        .unwrap()
        .unwrap();

    assert_eq!(view.spec.id, spec_id(1));
    assert_eq!(view.operation_count, 2);
    assert_eq!(view.diff.added().len(), 2);
    assert_eq!(view.diff.removed().len(), 0);
}

#[tokio::test]
async fn a_draft_is_compared_with_the_union_of_the_active_versions_and_the_grants_of_the_roles() {
    let first = spec(
        1,
        SpecStatus::Active,
        &[
            (HttpMethod::Get, "/invoices", NONE),
            (HttpMethod::Post, "/invoices", NONE.with_sensitive()),
        ],
    );
    let second = spec(
        2,
        SpecStatus::Active,
        &[(HttpMethod::Get, "/refunds", NONE)],
    );
    let draft = spec(
        3,
        SpecStatus::Draft,
        &[
            (HttpMethod::Get, "/invoices", NONE),
            (HttpMethod::Get, "/orders", NONE),
        ],
    );
    let roles = FakeRoleRepository::holding(vec![
        role(1, &["rest:billing:POST /invoices"]),
        role(2, &["rest:billing:GET *"]),
    ]);
    let handler = handler(repository(&[first, second, draft]), roles);

    let view = handler
        .handle(GetOpenApiSpecDiffQuery { id: spec_id(3) })
        .await
        .unwrap()
        .unwrap();

    let added: Vec<String> = view.diff.added().iter().map(ToString::to_string).collect();
    let removed: Vec<String> = view
        .diff
        .removed()
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(added, ["GET /orders"]);
    assert_eq!(removed, ["GET /refunds", "POST /invoices"]);
    assert_eq!(view.diff.removed_grants().len(), 1);
    assert_eq!(view.diff.removed_grants()[0].roles, [role_id(1)]);
    assert_eq!(view.diff.wildcard_gains().len(), 1);
    assert_eq!(view.diff.wildcard_gains()[0].role, role_id(2));
    assert_eq!(view.diff.flag_downgrades().len(), 0);
}

#[tokio::test]
async fn every_page_of_roles_is_weighed() {
    let active = spec(
        1,
        SpecStatus::Active,
        &[(HttpMethod::Get, "/invoices", NONE)],
    );
    let draft = spec(2, SpecStatus::Draft, &[(HttpMethod::Get, "/orders", NONE)]);
    let mut roles: Vec<RoleParts> = (1..=100).map(|number| role(number, &[])).collect();
    roles.push(role(101, &["rest:billing:GET /invoices"]));
    let handler = handler(
        repository(&[active, draft]),
        FakeRoleRepository::holding(roles),
    );

    let view = handler
        .handle(GetOpenApiSpecDiffQuery { id: spec_id(2) })
        .await
        .unwrap()
        .unwrap();

    assert_eq!(view.diff.removed_grants().len(), 1);
    assert_eq!(view.diff.removed_grants()[0].roles, [role_id(101)]);
}

#[tokio::test]
async fn an_unavailable_repository_is_a_storage_error() {
    let unavailable_specs = handler(
        Arc::new(FakeOpenApiSpecRepository::failing()),
        FakeRoleRepository::new(),
    );
    let unavailable_roles = handler(
        repository(&[spec(1, SpecStatus::Draft, &[(HttpMethod::Get, "/a", NONE)])]),
        FakeRoleRepository::failing(),
    );

    for handler in [unavailable_specs, unavailable_roles] {
        let error = handler
            .handle(GetOpenApiSpecDiffQuery { id: spec_id(1) })
            .await
            .unwrap_err();
        assert!(matches!(error, IamError::Storage(_)));
    }
}
