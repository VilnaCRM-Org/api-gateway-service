use std::time::{Duration, SystemTime};

use shared_domain::Uuid;

use super::{
    AssignedRole, PrivilegedRoleAssigned, UserRoleAssigned, UserRoleRevoked, UserRoleUpdated,
};
use crate::entity::event_envelope::{EventEnvelope, IamDomainEvent};
use crate::error::InvalidEventEnvelope;
use crate::user_role::RevocationCause;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::assignment_expiry::AssignmentExpiry;
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::event_data::{EventData, EventValue};
use crate::value_object::identifier::{ProjectId, RoleId, UserRoleId};
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::role_name::RoleName;
use crate::value_object::service_name::ServiceName;
use crate::value_object::subject::SubjectRef;

const EVENT: &str = "01890a5d-ac96-774b-bcce-b302099a8057";
const USER_ROLE: &str = "0b7e5d3c-2a19-4f8e-8d6c-5b4a39281706";
const ROLE: &str = "7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b";
const PROJECT: &str = "5e4d3c2b-1a09-4f8e-a7d6-c5b4a3928170";
const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";
const SUBJECT: &str = "9c8b7a6f-5e4d-4c3b-a291-807f6e5d4c3b";
const EXPIRY_SECONDS: u64 = 1_800_000_000;
const EXPIRY_MICROS: i64 = 1_800_000_000_000_000;

fn event_id() -> Uuid {
    Uuid::parse(EVENT).unwrap()
}

fn user_role_id() -> UserRoleId {
    UserRoleId::parse(USER_ROLE).unwrap()
}

fn actor() -> ActorRef {
    ActorRef::User(Uuid::parse(USER).unwrap())
}

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(1_700_000_000))
        .unwrap()
}

fn expiry() -> AssignmentExpiry {
    AssignmentExpiry::restore(
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(EXPIRY_SECONDS))
            .unwrap(),
    )
}

fn expiry_micros() -> EventValue {
    EventValue::Integer(EXPIRY_MICROS)
}

fn version(value: i64) -> EntityVersion {
    EntityVersion::new(value).unwrap()
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

fn user() -> SubjectRef {
    SubjectRef::user(Uuid::parse(SUBJECT).unwrap())
}

fn service() -> SubjectRef {
    SubjectRef::service(ServiceName::new("billing-service").unwrap())
}

fn subject_object(kind: &str, id: &str) -> EventValue {
    EventValue::Object(data(vec![("kind", text(kind)), ("id", text(id))]))
}

fn role(subject: SubjectRef, scope: AssignmentScope) -> AssignedRole {
    AssignedRole {
        subject,
        role_id: RoleId::parse(ROLE).unwrap(),
        role_name: RoleName::new("Billing".to_owned()).unwrap(),
        scope,
    }
}

fn project() -> AssignmentScope {
    AssignmentScope::Project(ProjectId::parse(PROJECT).unwrap())
}

/// Checks the common accessors of an assignment event and that it has an envelope.
fn assert_common(event: &dyn IamDomainEvent, name: &str, expected_version: i64) {
    assert_eq!(event.event_name(), name);
    assert_eq!(event.event_id(), event_id());
    assert_eq!(event.aggregate_id(), user_role_id().as_uuid());
    assert_eq!(event.occurred_at(), at());
    assert_eq!(event.actor(), &actor());
    assert_eq!(event.entity_version(), Some(version(expected_version)));
    let envelope = EventEnvelope::of(event).unwrap();
    assert_eq!(envelope.parts().event_type.as_str(), name);
}

fn assigned(subject: SubjectRef, expires_at: Option<AssignmentExpiry>) -> UserRoleAssigned {
    UserRoleAssigned {
        event_id: event_id(),
        user_role_id: user_role_id(),
        version: EntityVersion::INITIAL,
        role: role(subject, project()),
        expires_at,
        actor: actor(),
        occurred_at: at(),
    }
}

#[test]
fn user_role_assigned_of_a_user_carries_the_user_id_and_the_expiry() {
    let event = assigned(user(), Some(expiry()));

    assert_eq!(UserRoleAssigned::NAME, "iam.user_role.assigned");
    assert_common(&event, UserRoleAssigned::NAME, 1);
    assert_eq!(
        event.data(),
        Ok(data(vec![
            ("userRoleId", text(USER_ROLE)),
            ("subject", subject_object("user", SUBJECT)),
            ("userId", text(SUBJECT)),
            ("roleId", text(ROLE)),
            ("roleName", text("Billing")),
            ("scope", text(&format!("project:{PROJECT}"))),
            ("expiresAt", expiry_micros()),
        ]))
    );
}

#[test]
fn user_role_assigned_of_a_service_carries_no_user_id_and_a_null_expiry() {
    let event = UserRoleAssigned {
        role: role(service(), AssignmentScope::Global),
        ..assigned(service(), None)
    };

    assert_eq!(
        event.data(),
        Ok(data(vec![
            ("userRoleId", text(USER_ROLE)),
            ("subject", subject_object("service", "billing-service")),
            ("roleId", text(ROLE)),
            ("roleName", text("Billing")),
            ("scope", text("global")),
            ("expiresAt", EventValue::Null),
        ]))
    );
}

#[test]
fn an_expiry_before_1970_cannot_be_published() {
    let before = AssignmentExpiry::restore(
        SystemTime::UNIX_EPOCH
            .checked_sub(Duration::from_secs(1))
            .unwrap(),
    );

    assert_eq!(
        assigned(user(), Some(before)).data(),
        Err(InvalidEventEnvelope::Timestamp)
    );
}

#[test]
fn privileged_role_assigned_adds_the_privileged_keys() {
    let event = PrivilegedRoleAssigned {
        event_id: event_id(),
        user_role_id: user_role_id(),
        version: EntityVersion::INITIAL,
        role: role(user(), project()),
        expires_at: None,
        privileged_keys: vec![
            PermissionGrant::parse("iam:audit:read").unwrap(),
            PermissionGrant::parse("rest:billing:*").unwrap(),
        ],
        actor: actor(),
        occurred_at: at(),
    };

    assert_eq!(PrivilegedRoleAssigned::NAME, "iam.privileged_role.assigned");
    assert_common(&event, PrivilegedRoleAssigned::NAME, 1);
    assert_eq!(
        event.data(),
        Ok(data(vec![
            ("userRoleId", text(USER_ROLE)),
            ("subject", subject_object("user", SUBJECT)),
            ("userId", text(SUBJECT)),
            ("roleId", text(ROLE)),
            ("roleName", text("Billing")),
            ("scope", text(&format!("project:{PROJECT}"))),
            ("expiresAt", EventValue::Null),
            (
                "privilegedKeys",
                EventValue::List(vec![text("iam:audit:read"), text("rest:billing:*")])
            ),
        ]))
    );
}

#[test]
fn user_role_updated_carries_the_subject_and_the_new_expiry() {
    let event = UserRoleUpdated {
        event_id: event_id(),
        user_role_id: user_role_id(),
        version: version(2),
        subject: service(),
        expires_at: Some(expiry()),
        actor: actor(),
        occurred_at: at(),
    };

    assert_eq!(UserRoleUpdated::NAME, "iam.user_role.updated");
    assert_common(&event, UserRoleUpdated::NAME, 2);
    assert_eq!(
        event.data(),
        Ok(data(vec![
            ("userRoleId", text(USER_ROLE)),
            ("subject", subject_object("service", "billing-service")),
            ("expiresAt", expiry_micros()),
        ]))
    );
}

#[test]
fn user_role_updated_with_a_cleared_expiry_carries_null() {
    let event = UserRoleUpdated {
        event_id: event_id(),
        user_role_id: user_role_id(),
        version: version(2),
        subject: user(),
        expires_at: None,
        actor: actor(),
        occurred_at: at(),
    };

    assert_eq!(
        event.data(),
        Ok(data(vec![
            ("userRoleId", text(USER_ROLE)),
            ("subject", subject_object("user", SUBJECT)),
            ("expiresAt", EventValue::Null),
        ]))
    );
}

#[test]
fn user_role_revoked_carries_the_role_and_the_cause() {
    let event = UserRoleRevoked {
        event_id: event_id(),
        user_role_id: user_role_id(),
        version: version(3),
        role: role(user(), AssignmentScope::Global),
        cause: RevocationCause::RoleDeleted,
        actor: actor(),
        occurred_at: at(),
    };

    assert_eq!(UserRoleRevoked::NAME, "iam.user_role.revoked");
    assert_common(&event, UserRoleRevoked::NAME, 3);
    assert_eq!(
        event.data(),
        Ok(data(vec![
            ("userRoleId", text(USER_ROLE)),
            ("subject", subject_object("user", SUBJECT)),
            ("userId", text(SUBJECT)),
            ("roleId", text(ROLE)),
            ("roleName", text("Billing")),
            ("scope", text("global")),
            ("cause", text("role_deleted")),
        ]))
    );
}
