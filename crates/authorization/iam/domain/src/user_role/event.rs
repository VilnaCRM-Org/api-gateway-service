//! The domain events of the `UserRole` aggregate, published on `iam.events.v1`.

use std::time::SystemTime;

use shared_domain::{DomainEvent, Uuid};

use crate::entity::event_envelope::IamDomainEvent;
use crate::error::InvalidEventEnvelope;
use crate::micros;
use crate::user_role::RevocationCause;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::assignment_expiry::AssignmentExpiry;
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::event_data::{EventData, EventValue};
use crate::value_object::identifier::{RoleId, UserRoleId};
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::role_name::RoleName;
use crate::value_object::subject::{SubjectId, SubjectRef};

/// Implements [`DomainEvent`] and [`IamDomainEvent`] for an assignment event with the fields
/// `event_id`, `user_role_id`, `version`, `actor` and `occurred_at` and an inherent `event_data`
/// method.
macro_rules! user_role_event {
    ($event:ident, $name:literal) => {
        impl $event {
            /// The type of the event on `iam.events.v1`.
            pub const NAME: &'static str = $name;
        }

        impl DomainEvent for $event {
            fn event_id(&self) -> Uuid {
                self.event_id
            }

            fn aggregate_id(&self) -> Uuid {
                self.user_role_id.as_uuid()
            }

            fn occurred_at(&self) -> SystemTime {
                self.occurred_at
            }

            fn event_name(&self) -> &'static str {
                Self::NAME
            }
        }

        impl IamDomainEvent for $event {
            fn actor(&self) -> &ActorRef {
                &self.actor
            }

            fn entity_version(&self) -> Option<EntityVersion> {
                Some(self.version)
            }

            fn data(&self) -> Result<EventData, InvalidEventEnvelope> {
                self.event_data()
            }
        }
    };
}

/// The subject, the role and the scope of an assignment, as its events describe them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignedRole {
    /// Who holds the role.
    pub subject: SubjectRef,
    /// The assigned role.
    pub role_id: RoleId,
    /// The name of the role at the time of the event.
    pub role_name: RoleName,
    /// Where the role applies.
    pub scope: AssignmentScope,
}

impl AssignedRole {
    /// `userRoleId`, `subject {kind, id}`, `userId` for a user subject, `roleId`, `roleName` and
    /// `scope`.
    fn event_data(&self, user_role_id: UserRoleId) -> Result<EventData, InvalidEventEnvelope> {
        let data = EventData::new()
            .with("userRoleId", text(&user_role_id))?
            .with("subject", subject(&self.subject)?)?;
        let data = match self.subject.id() {
            SubjectId::User(user_id) => data.with("userId", text(user_id))?,
            SubjectId::Service(_) => data,
        };
        data.with("roleId", text(&self.role_id))?
            .with("roleName", text(&self.role_name))?
            .with("scope", text(&self.scope))
    }
}

/// A role was assigned to a subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRoleAssigned {
    /// The id of the event.
    pub event_id: Uuid,
    /// The created assignment.
    pub user_role_id: UserRoleId,
    /// The version of the assignment after the change: 1.
    pub version: EntityVersion,
    /// The subject, the role and the scope.
    pub role: AssignedRole,
    /// When the assignment expires.
    pub expires_at: Option<AssignmentExpiry>,
    /// Who assigned the role.
    pub actor: ActorRef,
    /// When the role was assigned.
    pub occurred_at: SystemTime,
}

user_role_event!(UserRoleAssigned, "iam.user_role.assigned");

impl UserRoleAssigned {
    /// The fields of [`AssignedRole`] and `expiresAt`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        self.role
            .event_data(self.user_role_id)?
            .with("expiresAt", expiry(self.expires_at)?)
    }
}

/// A role holding a wildcard or a reserved key was assigned: a security alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegedRoleAssigned {
    /// The id of the event.
    pub event_id: Uuid,
    /// The created assignment.
    pub user_role_id: UserRoleId,
    /// The version of the assignment after the change: 1.
    pub version: EntityVersion,
    /// The subject, the role and the scope.
    pub role: AssignedRole,
    /// When the assignment expires.
    pub expires_at: Option<AssignmentExpiry>,
    /// The wildcards and reserved keys of the role, in order.
    pub privileged_keys: Vec<PermissionGrant>,
    /// Who assigned the role.
    pub actor: ActorRef,
    /// When the role was assigned.
    pub occurred_at: SystemTime,
}

user_role_event!(PrivilegedRoleAssigned, "iam.privileged_role.assigned");

impl PrivilegedRoleAssigned {
    /// The fields of [`UserRoleAssigned`] and `privilegedKeys`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        let keys = self.privileged_keys.iter().map(text).collect();
        self.role
            .event_data(self.user_role_id)?
            .with("expiresAt", expiry(self.expires_at)?)?
            .with("privilegedKeys", EventValue::List(keys))
    }
}

/// The expiry of an assignment changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRoleUpdated {
    /// The id of the event.
    pub event_id: Uuid,
    /// The changed assignment.
    pub user_role_id: UserRoleId,
    /// The version of the assignment after the change.
    pub version: EntityVersion,
    /// Who holds the role.
    pub subject: SubjectRef,
    /// The new expiry; `None` when it was cleared.
    pub expires_at: Option<AssignmentExpiry>,
    /// Who changed the assignment.
    pub actor: ActorRef,
    /// When the assignment changed.
    pub occurred_at: SystemTime,
}

user_role_event!(UserRoleUpdated, "iam.user_role.updated");

impl UserRoleUpdated {
    /// `userRoleId`, `subject {kind, id}` and `expiresAt`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        EventData::new()
            .with("userRoleId", text(&self.user_role_id))?
            .with("subject", subject(&self.subject)?)?
            .with("expiresAt", expiry(self.expires_at)?)
    }
}

/// An assignment was revoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRoleRevoked {
    /// The id of the event.
    pub event_id: Uuid,
    /// The revoked assignment.
    pub user_role_id: UserRoleId,
    /// The version of the assignment after the change.
    pub version: EntityVersion,
    /// The subject, the role and the scope.
    pub role: AssignedRole,
    /// Why the assignment was revoked.
    pub cause: RevocationCause,
    /// Who revoked the assignment.
    pub actor: ActorRef,
    /// When the assignment was revoked.
    pub occurred_at: SystemTime,
}

user_role_event!(UserRoleRevoked, "iam.user_role.revoked");

impl UserRoleRevoked {
    /// The fields of [`AssignedRole`] and `cause`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        self.role
            .event_data(self.user_role_id)?
            .with("cause", EventValue::Text(self.cause.as_str().to_owned()))
    }
}

/// The text form of a value.
fn text(value: &impl std::fmt::Display) -> EventValue {
    EventValue::Text(value.to_string())
}

/// The subject as the object `{kind, id}`.
fn subject(subject: &SubjectRef) -> Result<EventValue, InvalidEventEnvelope> {
    EventData::new()
        .with("kind", EventValue::Text(subject.kind().as_str().to_owned()))?
        .with("id", text(subject.id()))
        .map(EventValue::Object)
}

/// The expiry in whole microseconds since 1970, or null for an assignment that never expires.
///
/// # Errors
///
/// [`InvalidEventEnvelope::Timestamp`] for an expiry before 1970 or past the microseconds that 64
/// bits hold.
fn expiry(expires_at: Option<AssignmentExpiry>) -> Result<EventValue, InvalidEventEnvelope> {
    expires_at.map_or(Ok(EventValue::Null), |expiry| {
        micros::since_epoch(expiry.at())
            .map(EventValue::Integer)
            .ok_or(InvalidEventEnvelope::Timestamp)
    })
}

#[cfg(test)]
mod tests;
