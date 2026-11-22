use std::time::{Duration, SystemTime};

use shared_domain::Uuid;

use super::UserRoleStatement;
use crate::user_role::{UserRole, UserRoleAssignment, UserRoleStamp};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::identifier::{RoleId, UserRoleId};
use crate::value_object::role_name::RoleName;
use crate::value_object::subject::SubjectRef;

fn user_role() -> UserRole {
    UserRole::assign(
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
            occurred_at: SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(1_700_000_000))
                .unwrap(),
        },
    )
    .unwrap()
}

#[test]
fn an_insert_carries_the_state_of_the_assignment_and_expects_no_version() {
    let user_role = user_role();

    let statement = UserRoleStatement::insert(&user_role);

    assert_eq!(statement.user_role(), user_role.parts());
    assert_eq!(statement.expected(), None);
}

#[test]
fn an_update_carries_the_state_of_the_assignment_and_the_expected_version() {
    let user_role = user_role();
    let expected = EntityVersion::new(4).unwrap();

    let statement = UserRoleStatement::update(&user_role, expected);

    assert_eq!(statement.user_role(), user_role.parts());
    assert_eq!(statement.expected(), Some(expected));
}
