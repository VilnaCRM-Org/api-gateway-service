use std::time::SystemTime;

use shared_domain::Uuid;

use super::ChangeStatement;
use crate::role::statement::RoleStatement;
use crate::role::{Role, RoleFields, RoleStamp};
use crate::user_role::statement::UserRoleStatement;
use crate::user_role::{UserRole, UserRoleAssignment, UserRoleStamp};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::identifier::{RoleId, UserRoleId};
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::role_name::RoleName;
use crate::value_object::subject::SubjectRef;

#[test]
fn an_expected_policy_version_holds_only_for_that_version() {
    let statement = ChangeStatement::ExpectPolicyVersion(PolicyVersion::new(4).unwrap());

    assert!(statement.holds(PolicyVersion::new(4).unwrap()));
    assert!(!statement.holds(PolicyVersion::new(5).unwrap()));
}

#[test]
fn a_role_write_holds_under_every_locked_version() {
    let actor = ActorRef::User(Uuid::parse("3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a").unwrap());
    let role = Role::create(
        RoleId::parse("7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b").unwrap(),
        RoleFields::new("Billing".to_owned(), None).unwrap(),
        RoleStamp {
            event_id: Uuid::parse("01890a5d-ac96-774b-bcce-b302099a8057").unwrap(),
            actor: actor.clone(),
            occurred_at: SystemTime::UNIX_EPOCH,
        },
    );
    let statement = ChangeStatement::SaveRole(Box::new(RoleStatement::insert(&role, actor)));

    assert!(statement.holds(PolicyVersion::new(1).unwrap()));
    assert!(statement.holds(PolicyVersion::new(9).unwrap()));
}

#[test]
fn an_assignment_write_holds_under_every_locked_version() {
    let user_role = UserRole::assign(
        UserRoleAssignment {
            id: UserRoleId::parse("0b7e5d3c-2a19-4f8e-8d6c-5b4a39281706").unwrap(),
            subject: SubjectRef::user(Uuid::parse("9c8b7a6f-5e4d-4c3b-a291-807f6e5d4c3b").unwrap()),
            role_id: RoleId::parse("7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b").unwrap(),
            role_name: RoleName::new("Billing".to_owned()).unwrap(),
            scope: AssignmentScope::Global,
            expires_at: None,
            privileged: None,
        },
        UserRoleStamp {
            event_id: Uuid::parse("01890a5d-ac96-774b-bcce-b302099a8057").unwrap(),
            actor: ActorRef::User(Uuid::parse("3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a").unwrap()),
            occurred_at: SystemTime::UNIX_EPOCH,
        },
    )
    .unwrap();
    let statement = ChangeStatement::SaveUserRole(Box::new(UserRoleStatement::insert(&user_role)));

    assert!(statement.holds(PolicyVersion::new(1).unwrap()));
    assert!(statement.holds(PolicyVersion::new(9).unwrap()));
}
