use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AssignmentExpiry, AssignmentScope, AuditOutcome, ChangeId, ChangeStatement,
    DecisionEffect, EntityVersion, IamUnitOfWork, PermissionGrant, PermissionGrantSet,
    PlatformAdministrator, ProjectId, RoleId, RoleKind, RoleName, RoleParts, SubjectRef,
    SystemComponent, UserRoleId, UserRoleParts,
};
use shared_domain::{Command as _, CommandHandler as _, Uuid};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::role::FakeRoleRepository;
use test_support::unit_of_work::FakeIamUnitOfWork;
use test_support::user_role::FakeUserRoleRepository;

use super::{BootstrapIamCommand, BootstrapIamCommandHandler, PAGE, grants_of};
use crate::error::IamError;

const CHANGE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ac";
const ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";
const USER_ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ae";
const ADMIN: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890af";
const OTHER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890b0";

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn command(subject: SubjectRef) -> BootstrapIamCommand {
    BootstrapIamCommand {
        change_id: ChangeId::parse(CHANGE).unwrap(),
        role_id: RoleId::parse(ROLE).unwrap(),
        user_role_id: UserRoleId::parse(USER_ROLE).unwrap(),
        subject,
    }
}

fn user() -> SubjectRef {
    SubjectRef::user(Uuid::parse(ADMIN).unwrap())
}

fn all_grants() -> PermissionGrantSet {
    PermissionGrantSet::new(
        PlatformAdministrator::GRANTS
            .iter()
            .map(|text| PermissionGrant::parse(text).unwrap()),
    )
    .unwrap()
}

fn stored_role(grants: PermissionGrantSet) -> RoleParts {
    RoleParts {
        id: RoleId::parse(ROLE).unwrap(),
        name: RoleName::new("iam-platform-admin".to_owned()).unwrap(),
        description: None,
        kind: RoleKind::System,
        grants,
        version: EntityVersion::new(2).unwrap(),
        created_at: SystemTime::UNIX_EPOCH,
        updated_at: SystemTime::UNIX_EPOCH,
        deleted_at: None,
    }
}

fn assignment(id: &str, expires_at: Option<SystemTime>) -> UserRoleParts {
    UserRoleParts {
        id: UserRoleId::parse(id).unwrap(),
        subject: user(),
        role_id: RoleId::parse(ROLE).unwrap(),
        scope: AssignmentScope::Global,
        expires_at: expires_at.map(AssignmentExpiry::restore),
        version: EntityVersion::INITIAL,
        created_by: ActorRef::System(SystemComponent::Bootstrap),
        created_at: SystemTime::UNIX_EPOCH,
        updated_at: SystemTime::UNIX_EPOCH,
        revoked_at: None,
    }
}

fn handler(
    roles: FakeRoleRepository,
    user_roles: FakeUserRoleRepository,
    unit_of_work: &Arc<FakeIamUnitOfWork>,
) -> BootstrapIamCommandHandler {
    let unit_of_work: Arc<dyn IamUnitOfWork> = Arc::<FakeIamUnitOfWork>::clone(unit_of_work);
    BootstrapIamCommandHandler::new(
        Arc::new(roles),
        Arc::new(user_roles),
        unit_of_work,
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    )
}

fn empty(unit_of_work: &Arc<FakeIamUnitOfWork>) -> BootstrapIamCommandHandler {
    handler(
        FakeRoleRepository::new(),
        FakeUserRoleRepository::new(),
        unit_of_work,
    )
}

fn types(change: &iam_domain::IamChange) -> Vec<&str> {
    change
        .parts()
        .events
        .iter()
        .map(|event| event.parts().event_type.as_str())
        .collect()
}

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(BootstrapIamCommand::NAME, "BootstrapIamCommand");
}

#[tokio::test]
async fn an_empty_database_gets_the_system_role_and_the_global_assignment_in_one_change() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    empty(&unit_of_work).handle(command(user())).await.unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed.len(), 1);
    let parts = committed[0].parts();
    assert_eq!(parts.change_id, command(user()).change_id);
    assert_eq!(parts.effect, DecisionEffect::Affected);
    assert_eq!(parts.entity_version, EntityVersion::INITIAL);
    let [
        ChangeStatement::SaveRole(role),
        ChangeStatement::SaveUserRole(user_role),
    ] = parts.statements.as_slice()
    else {
        panic!(
            "a role insert and an assignment insert expected: {:?}",
            parts.statements
        );
    };
    assert_eq!(role.expected(), None);
    assert_eq!(role.role().kind, RoleKind::System);
    assert_eq!(role.role().name.as_str(), "iam-platform-admin");
    assert_eq!(role.role().grants, all_grants());
    assert_eq!(role.actor(), &ActorRef::System(SystemComponent::Bootstrap));
    assert_eq!(user_role.expected(), None);
    assert_eq!(user_role.user_role().scope, AssignmentScope::Global);
    assert_eq!(user_role.user_role().subject, user());
    assert_eq!(user_role.user_role().role_id, role.role().id);
    assert_eq!(user_role.user_role().expires_at, None);
}

#[tokio::test]
async fn the_change_records_the_role_events_the_assignment_and_the_privileged_alert() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    empty(&unit_of_work).handle(command(user())).await.unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(
        types(&committed[0]),
        [
            "iam.role.created",
            "iam.role_permissions.changed",
            "iam.user_role.assigned",
            "iam.privileged_role.assigned",
        ]
    );
}

#[tokio::test]
async fn the_audit_record_names_the_bootstrap_as_actor() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    empty(&unit_of_work).handle(command(user())).await.unwrap();

    let committed = unit_of_work.committed();
    let audit = committed[0].parts().audit.parts();
    assert_eq!(audit.actor.to_string(), "system:bootstrap");
    assert_eq!(audit.action.as_str(), "iam.bootstrap");
    assert_eq!(audit.outcome, AuditOutcome::Committed);
    assert_eq!(audit.target.target_type(), "user_role");
    assert_eq!(audit.target.target_id(), USER_ROLE);
    assert_eq!(audit.scope, Some(AssignmentScope::Global));
    assert_eq!(audit.occurred_at, at());
}

#[tokio::test]
async fn a_service_principal_can_be_the_first_administrator() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let subject = SubjectRef::new(iam_domain::SubjectKind::Service, "schemathesis").unwrap();

    empty(&unit_of_work)
        .handle(command(subject.clone()))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let [_role, ChangeStatement::SaveUserRole(user_role)] =
        committed[0].parts().statements.as_slice()
    else {
        panic!("{:?}", committed[0].parts().statements);
    };
    assert_eq!(user_role.user_role().subject, subject);
}

#[tokio::test]
async fn an_active_global_assignment_refuses_the_bootstrap_and_changes_nothing() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let handler = handler(
        FakeRoleRepository::holding(vec![stored_role(all_grants())]),
        FakeUserRoleRepository::holding(vec![assignment(OTHER, None)]),
        &unit_of_work,
    );

    let error = handler.handle(command(user())).await.unwrap_err();

    assert!(matches!(error, IamError::Conflict), "{error:?}");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn an_existing_complete_role_without_an_active_assignment_is_only_assigned() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let expired = assignment(OTHER, Some(at()));
    let handler = handler(
        FakeRoleRepository::holding(vec![stored_role(all_grants())]),
        FakeUserRoleRepository::holding(vec![expired]),
        &unit_of_work,
    );

    handler.handle(command(user())).await.unwrap();

    let committed = unit_of_work.committed();
    let statements = &committed[0].parts().statements;
    assert!(
        matches!(statements.as_slice(), [ChangeStatement::SaveUserRole(_)]),
        "{statements:?}"
    );
    assert_eq!(
        types(&committed[0]),
        ["iam.user_role.assigned", "iam.privileged_role.assigned"]
    );
}

#[tokio::test]
async fn an_existing_role_with_other_grants_gets_every_key_back_at_its_version() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let partial =
        PermissionGrantSet::new([PermissionGrant::parse("iam:audit:read").unwrap()]).unwrap();
    let handler = handler(
        FakeRoleRepository::holding(vec![stored_role(partial)]),
        FakeUserRoleRepository::new(),
        &unit_of_work,
    );

    handler.handle(command(user())).await.unwrap();

    let committed = unit_of_work.committed();
    let [
        ChangeStatement::SaveRole(role),
        ChangeStatement::SaveUserRole(_),
    ] = committed[0].parts().statements.as_slice()
    else {
        panic!("{:?}", committed[0].parts().statements);
    };
    assert_eq!(role.expected(), Some(EntityVersion::new(2).unwrap()));
    assert_eq!(role.role().version, EntityVersion::new(3).unwrap());
    assert_eq!(role.role().grants, all_grants());
}

#[tokio::test]
async fn a_custom_role_of_the_same_name_is_not_the_administrator_role() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let custom = RoleParts {
        kind: RoleKind::Custom,
        ..stored_role(all_grants())
    };
    let handler = handler(
        FakeRoleRepository::holding(vec![custom]),
        FakeUserRoleRepository::new(),
        &unit_of_work,
    );

    handler.handle(command(user())).await.unwrap();

    let committed = unit_of_work.committed();
    assert!(matches!(
        committed[0].parts().statements.first(),
        Some(ChangeStatement::SaveRole(role)) if role.expected().is_none()
    ));
}

#[tokio::test]
async fn unreadable_storage_and_a_failing_unit_of_work_are_storage_failures() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let roles = handler(
        FakeRoleRepository::failing(),
        FakeUserRoleRepository::new(),
        &unit_of_work,
    )
    .handle(command(user()))
    .await
    .unwrap_err();
    let user_roles = handler(
        FakeRoleRepository::holding(vec![stored_role(all_grants())]),
        FakeUserRoleRepository::failing(),
        &unit_of_work,
    )
    .handle(command(user()))
    .await
    .unwrap_err();
    let failing = Arc::new(FakeIamUnitOfWork::failing());
    let commit = empty(&failing).handle(command(user())).await.unwrap_err();

    assert!(matches!(roles, IamError::Storage(_)), "{roles:?}");
    assert!(matches!(user_roles, IamError::Storage(_)), "{user_roles:?}");
    assert!(matches!(commit, IamError::Storage(_)), "{commit:?}");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[test]
fn a_grant_text_that_does_not_parse_is_an_internal_error() {
    let error = grants_of(&["rest:iam:*", "not a key"]).unwrap_err();

    assert!(matches!(error, IamError::Internal(_)), "{error:?}");
}

/// An assignment identifier that sorts by `number`.
fn numbered(number: u128) -> UserRoleId {
    UserRoleId::parse(&format!("00000000-0000-7000-8000-{number:012x}")).unwrap()
}

#[tokio::test]
async fn an_active_global_assignment_after_a_full_page_refuses_the_bootstrap() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let project = ProjectId::parse(OTHER).unwrap();
    let mut assignments: Vec<UserRoleParts> = (1..=u128::from(PAGE))
        .map(|number| UserRoleParts {
            id: numbered(number),
            scope: AssignmentScope::Project(project),
            ..assignment(OTHER, None)
        })
        .collect();
    assignments.push(UserRoleParts {
        id: numbered(u128::from(PAGE).saturating_add(1)),
        ..assignment(OTHER, None)
    });
    let handler = handler(
        FakeRoleRepository::holding(vec![stored_role(all_grants())]),
        FakeUserRoleRepository::holding(assignments),
        &unit_of_work,
    );

    let error = handler.handle(command(user())).await.unwrap_err();

    assert!(matches!(error, IamError::Conflict), "{error:?}");
    assert_eq!(unit_of_work.committed().len(), 0);
}
