//! The domain events of the `Role` aggregate, published on `iam.events.v1`.

use std::time::SystemTime;

use shared_domain::{DomainEvent, Uuid};

use crate::entity::event_envelope::IamDomainEvent;
use crate::error::InvalidEventEnvelope;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::event_data::{EventData, EventValue};
use crate::value_object::identifier::RoleId;
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::role_kind::RoleKind;
use crate::value_object::role_name::RoleName;

/// Implements [`DomainEvent`] and [`IamDomainEvent`] for a role event with the fields `event_id`,
/// `role_id`, `version`, `actor` and `occurred_at` and an inherent `event_data` method.
macro_rules! role_event {
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
                self.role_id.as_uuid()
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

/// A role was created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleCreated {
    /// The id of the event.
    pub event_id: Uuid,
    /// The created role.
    pub role_id: RoleId,
    /// The version of the role after the change: 1.
    pub version: EntityVersion,
    /// The name of the role.
    pub name: RoleName,
    /// The kind of the role.
    pub kind: RoleKind,
    /// Who created the role.
    pub actor: ActorRef,
    /// When the role was created.
    pub occurred_at: SystemTime,
}

role_event!(RoleCreated, "iam.role.created");

impl RoleCreated {
    /// `roleId`, `name` and `kind`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        EventData::new()
            .with("roleId", text(&self.role_id))?
            .with("name", text(&self.name))?
            .with("kind", text(&self.kind))
    }
}

/// The name or the description of a role changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleUpdated {
    /// The id of the event.
    pub event_id: Uuid,
    /// The changed role.
    pub role_id: RoleId,
    /// The version of the role after the change.
    pub version: EntityVersion,
    /// The new name, when it changed.
    pub name: Option<RoleName>,
    /// The names of the changed fields, in the order name, description.
    pub changed_fields: Vec<&'static str>,
    /// Who changed the role.
    pub actor: ActorRef,
    /// When the role changed.
    pub occurred_at: SystemTime,
}

role_event!(RoleUpdated, "iam.role.updated");

impl RoleUpdated {
    /// The changed-field name of the name.
    pub const NAME_FIELD: &'static str = "name";
    /// The changed-field name of the description.
    pub const DESCRIPTION_FIELD: &'static str = "description";

    /// `roleId`, `changedFields` and the new `name` when it changed; a description may span
    /// lines, so the event names it as changed without carrying it.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        let changed = self
            .changed_fields
            .iter()
            .map(|field| EventValue::Text((*field).to_owned()))
            .collect();
        let data = EventData::new()
            .with("roleId", text(&self.role_id))?
            .with("changedFields", EventValue::List(changed))?;
        match &self.name {
            Some(name) => data.with("name", text(name)),
            None => Ok(data),
        }
    }
}

/// A role was deleted, revoking every assignment of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleDeleted {
    /// The id of the event.
    pub event_id: Uuid,
    /// The deleted role.
    pub role_id: RoleId,
    /// The version of the role after the change.
    pub version: EntityVersion,
    /// The name of the role.
    pub name: RoleName,
    /// The number of assignments the deletion revoked.
    pub revoked_assignments: u32,
    /// Who deleted the role.
    pub actor: ActorRef,
    /// When the role was deleted.
    pub occurred_at: SystemTime,
}

role_event!(RoleDeleted, "iam.role.deleted");

impl RoleDeleted {
    /// `roleId`, `name` and `revokedAssignments`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        EventData::new()
            .with("roleId", text(&self.role_id))?
            .with("name", text(&self.name))?
            .with(
                "revokedAssignments",
                EventValue::Integer(i64::from(self.revoked_assignments)),
            )
    }
}

/// The grant set of a role was replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolePermissionsChanged {
    /// The id of the event.
    pub event_id: Uuid,
    /// The changed role.
    pub role_id: RoleId,
    /// The version of the role after the change.
    pub version: EntityVersion,
    /// The grants the replacement added, in order.
    pub added: Vec<PermissionGrant>,
    /// The grants the replacement removed, in order.
    pub removed: Vec<PermissionGrant>,
    /// Who replaced the grants.
    pub actor: ActorRef,
    /// When the grants were replaced.
    pub occurred_at: SystemTime,
}

role_event!(RolePermissionsChanged, "iam.role_permissions.changed");

impl RolePermissionsChanged {
    /// `roleId`, `addedKeys`, `removedKeys` and `wildcards`, the added wildcard patterns, which
    /// cover elements that do not exist yet.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        let wildcards: Vec<PermissionGrant> = self
            .added
            .iter()
            .filter(|grant| grant.is_wildcard())
            .cloned()
            .collect();
        EventData::new()
            .with("roleId", text(&self.role_id))?
            .with("addedKeys", texts(&self.added))?
            .with("removedKeys", texts(&self.removed))?
            .with("wildcards", texts(&wildcards))
    }
}

/// The text form of a value.
fn text(value: &impl std::fmt::Display) -> EventValue {
    EventValue::Text(value.to_string())
}

/// The text forms of grants, as a list.
fn texts(grants: &[PermissionGrant]) -> EventValue {
    EventValue::List(grants.iter().map(text).collect())
}

#[cfg(test)]
mod tests;
