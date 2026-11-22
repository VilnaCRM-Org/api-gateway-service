use std::time::{Duration, SystemTime};

use shared_domain::Uuid;

use super::{RoleCreated, RoleDeleted, RolePermissionsChanged, RoleUpdated};
use crate::entity::event_envelope::{EventEnvelope, IamDomainEvent};
use crate::error::InvalidEventEnvelope;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::event_data::{EventData, EventValue};
use crate::value_object::identifier::RoleId;
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::role_kind::RoleKind;
use crate::value_object::role_name::RoleName;

const EVENT: &str = "01890a5d-ac96-774b-bcce-b302099a8057";
const ROLE: &str = "7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b";
const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";

fn event_id() -> Uuid {
    Uuid::parse(EVENT).unwrap()
}

fn role_id() -> RoleId {
    RoleId::parse(ROLE).unwrap()
}

fn actor() -> ActorRef {
    ActorRef::User(Uuid::parse(USER).unwrap())
}

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(1_700_000_000))
        .unwrap()
}

fn version(value: i64) -> EntityVersion {
    EntityVersion::new(value).unwrap()
}

fn name(value: &str) -> RoleName {
    RoleName::new(value.to_owned()).unwrap()
}

fn grant(value: &str) -> PermissionGrant {
    PermissionGrant::parse(value).unwrap()
}

fn text(value: &str) -> EventValue {
    EventValue::Text(value.to_owned())
}

fn list(values: &[&str]) -> EventValue {
    EventValue::List(values.iter().map(|value| text(value)).collect())
}

fn data(fields: Vec<(&str, EventValue)>) -> EventData {
    fields
        .into_iter()
        .try_fold(EventData::new(), |data, (name, value)| {
            data.with(name, value)
        })
        .unwrap()
}

/// Checks the common accessors of a role event and that it has an envelope.
fn assert_common(event: &dyn IamDomainEvent, name: &str, expected_version: i64) {
    assert_eq!(event.event_name(), name);
    assert_eq!(event.event_id(), event_id());
    assert_eq!(event.aggregate_id(), role_id().as_uuid());
    assert_eq!(event.occurred_at(), at());
    assert_eq!(event.actor(), &actor());
    assert_eq!(event.entity_version(), Some(version(expected_version)));
    let envelope = EventEnvelope::of(event).unwrap();
    assert_eq!(envelope.parts().event_type.as_str(), name);
}

fn created() -> RoleCreated {
    RoleCreated {
        event_id: event_id(),
        role_id: role_id(),
        version: EntityVersion::INITIAL,
        name: name("Billing"),
        kind: RoleKind::Custom,
        actor: actor(),
        occurred_at: at(),
    }
}

fn updated(new_name: Option<RoleName>, changed_fields: Vec<&'static str>) -> RoleUpdated {
    RoleUpdated {
        event_id: event_id(),
        role_id: role_id(),
        version: version(2),
        name: new_name,
        changed_fields,
        actor: actor(),
        occurred_at: at(),
    }
}

#[test]
fn role_created_is_named_and_carries_the_id_the_name_and_the_kind() {
    let event = created();

    assert_eq!(RoleCreated::NAME, "iam.role.created");
    assert_common(&event, RoleCreated::NAME, 1);
    assert_eq!(
        event.data(),
        Ok(data(vec![
            ("roleId", text(ROLE)),
            ("name", text("Billing")),
            ("kind", text("custom")),
        ]))
    );
}

#[test]
fn role_updated_carries_the_changed_fields_and_the_new_name() {
    let event = updated(
        Some(name("Invoicing")),
        vec![RoleUpdated::NAME_FIELD, RoleUpdated::DESCRIPTION_FIELD],
    );

    assert_eq!(RoleUpdated::NAME, "iam.role.updated");
    assert_common(&event, RoleUpdated::NAME, 2);
    assert_eq!(
        event.data(),
        Ok(data(vec![
            ("roleId", text(ROLE)),
            ("changedFields", list(&["name", "description"])),
            ("name", text("Invoicing")),
        ]))
    );
}

#[test]
fn role_updated_without_a_new_name_carries_no_name() {
    let event = updated(None, vec![RoleUpdated::DESCRIPTION_FIELD]);

    assert_eq!(
        event.data(),
        Ok(data(vec![
            ("roleId", text(ROLE)),
            ("changedFields", list(&["description"])),
        ]))
    );
}

#[test]
fn role_updated_refuses_a_name_shaped_like_a_token() {
    let event = updated(
        Some(name("eyJhbGciOiJIUzI1NiJ9.e30.c2lnbmF0dXJl")),
        Vec::new(),
    );

    assert_eq!(event.data(), Err(InvalidEventEnvelope::Credential));
}

#[test]
fn role_created_refuses_a_name_shaped_like_a_token() {
    let event = RoleCreated {
        name: name("eyJhbGciOiJIUzI1NiJ9.e30.c2lnbmF0dXJl"),
        ..created()
    };

    assert_eq!(event.data(), Err(InvalidEventEnvelope::Credential));
}

#[test]
fn role_deleted_carries_the_name_and_the_number_of_revoked_assignments() {
    let event = RoleDeleted {
        event_id: event_id(),
        role_id: role_id(),
        version: version(4),
        name: name("Billing"),
        revoked_assignments: u32::MAX,
        actor: actor(),
        occurred_at: at(),
    };

    assert_eq!(RoleDeleted::NAME, "iam.role.deleted");
    assert_common(&event, RoleDeleted::NAME, 4);
    assert_eq!(
        event.data(),
        Ok(data(vec![
            ("roleId", text(ROLE)),
            ("name", text("Billing")),
            ("revokedAssignments", EventValue::Integer(4_294_967_295)),
        ]))
    );
}

#[test]
fn role_permissions_changed_carries_the_added_the_removed_and_the_wildcard_grants() {
    let event = RolePermissionsChanged {
        event_id: event_id(),
        role_id: role_id(),
        version: version(3),
        added: vec![grant("gql:billing:*"), grant("rest:billing:GET /invoices")],
        removed: vec![grant("gql:billing:Query.invoices")],
        actor: actor(),
        occurred_at: at(),
    };

    assert_eq!(RolePermissionsChanged::NAME, "iam.role_permissions.changed");
    assert_common(&event, RolePermissionsChanged::NAME, 3);
    assert_eq!(
        event.data(),
        Ok(data(vec![
            ("roleId", text(ROLE)),
            (
                "addedKeys",
                list(&["gql:billing:*", "rest:billing:GET /invoices"])
            ),
            ("removedKeys", list(&["gql:billing:Query.invoices"])),
            ("wildcards", list(&["gql:billing:*"])),
        ]))
    );
}
