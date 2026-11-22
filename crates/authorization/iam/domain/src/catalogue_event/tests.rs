use std::time::{Duration, SystemTime};

use shared_domain::Uuid;

use super::{GraphQlPermissionsCreated, PermissionsOrphaned, RestPermissionsCreated};
use crate::entity::event_envelope::{EventEnvelope, IamDomainEvent};
use crate::policy::catalogue_activation::{FlagChange, KeyRename};
use crate::value_object::actor_ref::{ActorRef, SystemComponent};
use crate::value_object::event_data::{EventData, EventValue};
use crate::value_object::identifier::{RoleId, SpecId};
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_key::PermissionKey;
use crate::value_object::service_name::ServiceName;

const EVENT: &str = "01890a5d-ac96-774b-bcce-b302099a8057";
const SPEC: &str = "5b2e8c1d-3f4a-4b6c-8d9e-0a1b2c3d4e5f";
const ADMIN: &str = "00000000-0000-4000-8000-000000000001";

fn event_id() -> Uuid {
    Uuid::parse(EVENT).unwrap()
}

fn spec_id() -> SpecId {
    SpecId::parse(SPEC).unwrap()
}

fn actor() -> ActorRef {
    ActorRef::System(SystemComponent::Startup)
}

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(1_700_000_000))
        .unwrap()
}

fn service() -> ServiceName {
    ServiceName::new("billing").unwrap()
}

fn key(value: &str) -> PermissionKey {
    PermissionKey::parse(value).unwrap()
}

fn text(value: &str) -> EventValue {
    EventValue::Text(value.to_owned())
}

fn data(fields: Vec<(&str, EventValue)>) -> EventData {
    fields
        .into_iter()
        .try_fold(EventData::new(), |data, (name, value)| {
            data.with(name, value)
        })
        .unwrap()
}

fn flags_value(flags: PermissionFlags) -> EventValue {
    EventValue::Object(data(vec![
        ("sensitive", EventValue::Bool(flags.is_sensitive())),
        ("auditAlways", EventValue::Bool(flags.is_audit_always())),
    ]))
}

fn renames() -> Vec<KeyRename> {
    vec![KeyRename {
        from: key("gql:billing:Query.bill"),
        to: key("gql:billing:Query.statement"),
        roles: vec![RoleId::parse(ADMIN).unwrap()],
    }]
}

fn flag_changes() -> Vec<FlagChange> {
    vec![FlagChange {
        key: key("gql:billing:Mutation.pay"),
        before: PermissionFlags::NONE.with_sensitive(),
        after: PermissionFlags::NONE.with_audit_always(),
    }]
}

/// Checks the common accessors of a catalogue event and that it has an envelope.
fn assert_common(event: &dyn IamDomainEvent, name: &str) {
    assert_eq!(event.event_name(), name);
    assert_eq!(event.event_id(), event_id());
    assert_eq!(event.aggregate_id(), spec_id().as_uuid());
    assert_eq!(event.occurred_at(), at());
    assert_eq!(event.actor(), &actor());
    assert_eq!(event.entity_version(), None);
    let envelope = EventEnvelope::of(event).unwrap();
    assert_eq!(envelope.parts().event_type.as_str(), name);
}

fn expected_created_data(created: &str) -> EventData {
    data(vec![
        ("specId", text(SPEC)),
        ("service", text("billing")),
        ("createdKeys", EventValue::List(vec![text(created)])),
        (
            "renamed",
            EventValue::List(vec![EventValue::Object(data(vec![
                ("from", text("gql:billing:Query.bill")),
                ("to", text("gql:billing:Query.statement")),
            ]))]),
        ),
        (
            "flagChanges",
            EventValue::List(vec![EventValue::Object(data(vec![
                ("key", text("gql:billing:Mutation.pay")),
                (
                    "before",
                    flags_value(PermissionFlags::NONE.with_sensitive()),
                ),
                (
                    "after",
                    flags_value(PermissionFlags::NONE.with_audit_always()),
                ),
            ]))]),
        ),
    ])
}

#[test]
fn graphql_keys_created_by_an_activation_name_the_renames_and_the_flag_changes() {
    let event = GraphQlPermissionsCreated {
        event_id: event_id(),
        spec_id: spec_id(),
        service: service(),
        created_keys: vec![key("gql:billing:Query.statement")],
        renamed: renames(),
        flag_changes: flag_changes(),
        actor: actor(),
        occurred_at: at(),
    };

    assert_eq!(
        GraphQlPermissionsCreated::NAME,
        "iam.graphql_permissions.created"
    );
    assert_common(&event, GraphQlPermissionsCreated::NAME);
    assert_eq!(
        event.data().unwrap(),
        expected_created_data("gql:billing:Query.statement")
    );
}

#[test]
fn rest_keys_created_by_an_activation_name_the_renames_and_the_flag_changes() {
    let event = RestPermissionsCreated {
        event_id: event_id(),
        spec_id: spec_id(),
        service: service(),
        created_keys: vec![key("rest:billing:GET /api/invoices")],
        renamed: renames(),
        flag_changes: flag_changes(),
        actor: actor(),
        occurred_at: at(),
    };

    assert_eq!(RestPermissionsCreated::NAME, "iam.rest_permissions.created");
    assert_common(&event, RestPermissionsCreated::NAME);
    assert_eq!(
        event.data().unwrap(),
        expected_created_data("rest:billing:GET /api/invoices")
    );
}

#[test]
fn an_activation_without_changes_carries_empty_lists() {
    let event = GraphQlPermissionsCreated {
        event_id: event_id(),
        spec_id: spec_id(),
        service: service(),
        created_keys: vec![],
        renamed: vec![],
        flag_changes: vec![],
        actor: actor(),
        occurred_at: at(),
    };

    assert_eq!(
        event.data().unwrap(),
        data(vec![
            ("specId", text(SPEC)),
            ("service", text("billing")),
            ("createdKeys", EventValue::List(vec![])),
            ("renamed", EventValue::List(vec![])),
            ("flagChanges", EventValue::List(vec![])),
        ])
    );
}

#[test]
fn orphaned_grants_name_the_keys_and_the_roles_that_lost_them() {
    let event = PermissionsOrphaned {
        event_id: event_id(),
        spec_id: spec_id(),
        service: service(),
        orphaned_keys: vec![key("gql:billing:Query.old")],
        affected_role_ids: vec![RoleId::parse(ADMIN).unwrap()],
        actor: actor(),
        occurred_at: at(),
    };

    assert_eq!(PermissionsOrphaned::NAME, "iam.permissions.orphaned");
    assert_common(&event, PermissionsOrphaned::NAME);
    assert_eq!(
        event.data().unwrap(),
        data(vec![
            ("specId", text(SPEC)),
            ("service", text("billing")),
            (
                "orphanedKeys",
                EventValue::List(vec![text("gql:billing:Query.old")])
            ),
            ("affectedRoleIds", EventValue::List(vec![text(ADMIN)])),
        ])
    );
}
