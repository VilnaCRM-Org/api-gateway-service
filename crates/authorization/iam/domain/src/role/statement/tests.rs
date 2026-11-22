use std::time::{Duration, SystemTime};

use shared_domain::Uuid;

use super::RoleStatement;
use crate::role::{Role, RoleFields, RoleStamp};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::identifier::RoleId;

const ROLE: &str = "7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b";
const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";
const EVENT: &str = "01890a5d-ac96-774b-bcce-b302099a8057";

fn actor() -> ActorRef {
    ActorRef::User(Uuid::parse(USER).unwrap())
}

fn role() -> Role {
    Role::create(
        RoleId::parse(ROLE).unwrap(),
        RoleFields::new("Billing".to_owned(), None).unwrap(),
        RoleStamp {
            event_id: Uuid::parse(EVENT).unwrap(),
            actor: actor(),
            occurred_at: SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(1_700_000_000))
                .unwrap(),
        },
    )
}

#[test]
fn an_insert_carries_the_state_of_the_role_and_expects_no_version() {
    let role = role();

    let statement = RoleStatement::insert(&role, actor());

    assert_eq!(statement.role(), role.parts());
    assert_eq!(statement.expected(), None);
    assert_eq!(statement.actor(), &actor());
}

#[test]
fn an_update_carries_the_state_of_the_role_and_the_expected_version() {
    let role = role();
    let expected = EntityVersion::new(3).unwrap();

    let statement = RoleStatement::update(&role, expected, actor());

    assert_eq!(statement.role(), role.parts());
    assert_eq!(statement.expected(), Some(expected));
    assert_eq!(statement.actor(), &actor());
}
