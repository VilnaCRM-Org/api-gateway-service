use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    AssignmentScope, CompiledRoleSet, EntityVersion, GrantStatus, PermissionGrant,
    PermissionGrantSet, PolicyReadRepository, ProjectId, RoleAssignment, RoleId, RoleKind,
    RoleName, RoleParts, RoleRepository, ServiceName, SubjectPolicy, SubjectRef,
};
use shared_domain::{Clock, Query as _, QueryHandler as _, Uuid};
use test_support::clock::FixedClock;
use test_support::policy_epoch::seeded_policy_epoch;
use test_support::policy_read::FakePolicyReadRepository;
use test_support::role::FakeRoleRepository;

use super::{GetUserRolePermissionsQuery, GetUserRolePermissionsQueryHandler};
use crate::error::IamError;

const NOW: u64 = 1_800_000_000;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn role(number: u32) -> RoleId {
    RoleId::parse(&format!("0190f2a8-7b3c-7d4e-8f10-{number:012x}")).unwrap()
}

fn project(number: u32) -> ProjectId {
    ProjectId::parse(&format!("0190f2a8-7b3c-7d4e-8f20-{number:012x}")).unwrap()
}

fn user() -> SubjectRef {
    SubjectRef::user(Uuid::parse("0190f2a8-7b3c-7d4e-8f30-000000000001").unwrap())
}

fn stored_role(number: u32) -> RoleParts {
    RoleParts {
        id: role(number),
        name: RoleName::new(format!("Role {number}")).unwrap(),
        description: None,
        kind: RoleKind::Custom,
        grants: PermissionGrantSet::new(Vec::<PermissionGrant>::new()).unwrap(),
        version: EntityVersion::new(1).unwrap(),
        created_at: SystemTime::UNIX_EPOCH,
        updated_at: SystemTime::UNIX_EPOCH,
        deleted_at: None,
    }
}

fn compiled(grants: &[&str]) -> CompiledRoleSet {
    CompiledRoleSet::compile(
        grants
            .iter()
            .map(|text| (PermissionGrant::parse(text).unwrap(), GrantStatus::Active)),
    )
}

fn policy() -> SubjectPolicy {
    SubjectPolicy::new(
        seeded_policy_epoch(),
        vec![
            RoleAssignment::new(role(1), AssignmentScope::Global, Some(at(NOW + 60))),
            RoleAssignment::new(role(2), AssignmentScope::Project(project(1)), None),
            RoleAssignment::new(
                role(1),
                AssignmentScope::Project(project(2)),
                Some(at(NOW - 1)),
            ),
        ],
        BTreeMap::from([
            (
                role(1),
                compiled(&["rest:billing:GET /invoices", "gql:core:*"]),
            ),
            (role(2), compiled(&["rest:billing:GET /invoices"])),
        ]),
    )
}

fn handler(
    policies: FakePolicyReadRepository,
    roles: Vec<RoleParts>,
) -> GetUserRolePermissionsQueryHandler {
    let policies: Arc<dyn PolicyReadRepository> = Arc::new(policies);
    let roles: Arc<dyn RoleRepository> = Arc::new(FakeRoleRepository::holding(roles));
    let clock: Arc<dyn Clock> = Arc::new(FixedClock::at(at(NOW)));
    GetUserRolePermissionsQueryHandler::new(policies, roles, clock)
}

fn asking(project: Option<ProjectId>, service: Option<&str>) -> GetUserRolePermissionsQuery {
    GetUserRolePermissionsQuery {
        subject: user(),
        project,
        service: service.map(|name| ServiceName::new(name).unwrap()),
    }
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(
        GetUserRolePermissionsQuery::NAME,
        "GetUserRolePermissionsQuery"
    );
}

#[tokio::test]
async fn the_effective_permissions_name_their_roles_and_the_policy_version() {
    let policies = FakePolicyReadRepository::new().with_subject(user(), policy());
    let handler = handler(policies, vec![stored_role(1), stored_role(2)]);

    let view = handler.handle(asking(None, None)).await.unwrap();

    assert_eq!(view.subject, user());
    assert_eq!(view.read_model.policy_version().value(), 0);
    let keys: Vec<String> = view
        .read_model
        .permissions()
        .iter()
        .map(|entry| entry.grant().to_string())
        .collect();
    assert_eq!(keys, ["rest:billing:GET /invoices", "gql:core:*"]);
    assert_eq!(
        view.role_names.get(&role(2)),
        Some(&Some(RoleName::new("Role 2".to_owned()).unwrap()))
    );
    assert_eq!(view.role_names.len(), 2);
}

#[tokio::test]
async fn the_project_and_service_narrow_the_answer() {
    let policies = FakePolicyReadRepository::new().with_subject(user(), policy());
    let handler = handler(policies, vec![stored_role(1), stored_role(2)]);

    let view = handler
        .handle(asking(Some(project(1)), Some("billing")))
        .await
        .unwrap();

    let keys: Vec<String> = view
        .read_model
        .permissions()
        .iter()
        .map(|entry| entry.grant().to_string())
        .collect();
    assert_eq!(keys, ["rest:billing:GET /invoices"]);
}

#[tokio::test]
async fn a_role_that_is_no_longer_stored_has_no_name() {
    let policies = FakePolicyReadRepository::new().with_subject(user(), policy());
    let handler = handler(policies, vec![stored_role(1)]);

    let view = handler.handle(asking(None, None)).await.unwrap();

    assert_eq!(view.role_names.get(&role(2)), Some(&None));
}

#[tokio::test]
async fn a_user_without_assignments_holds_nothing() {
    let handler = handler(FakePolicyReadRepository::new(), Vec::new());

    let view = handler.handle(asking(None, None)).await.unwrap();

    assert_eq!(view.read_model.permissions(), []);
    assert!(view.role_names.is_empty());
}

#[tokio::test]
async fn a_storage_failure_is_reported_as_unavailable_storage() {
    let handler = handler(FakePolicyReadRepository::failing(), Vec::new());

    let error = handler.handle(asking(None, None)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
