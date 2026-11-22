//! The domain events of the permission catalogue, published on `iam.events.v1`.
//!
//! They record the keys an activation created, renamed or re-flagged and the keys whose grants it
//! orphaned. They carry identifiers, the service and keys, never the specification (FR-32, FR-36,
//! FR-38).

use std::time::SystemTime;

use shared_domain::{DomainEvent, Uuid};

use crate::entity::event_envelope::IamDomainEvent;
use crate::error::InvalidEventEnvelope;
use crate::policy::catalogue_activation::{FlagChange, KeyRename};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::event_data::{EventData, EventValue};
use crate::value_object::identifier::{RoleId, SpecId};
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_key::PermissionKey;
use crate::value_object::service_name::ServiceName;

/// Implements [`DomainEvent`] and [`IamDomainEvent`] for a catalogue event with the fields
/// `event_id`, `spec_id`, `actor` and `occurred_at` and an inherent `event_data` method. The
/// catalogue is not versioned per entity, so the events name no entity version.
macro_rules! catalogue_event {
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
                self.spec_id.as_uuid()
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
                None
            }

            fn data(&self) -> Result<EventData, InvalidEventEnvelope> {
                self.event_data()
            }
        }
    };
}

/// An activation created GraphQL catalogue keys, renamed some and changed some flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphQlPermissionsCreated {
    /// The id of the event.
    pub event_id: Uuid,
    /// The activated version.
    pub spec_id: SpecId,
    /// The service of the schema.
    pub service: ServiceName,
    /// The keys the catalogue gained.
    pub created_keys: Vec<PermissionKey>,
    /// The renames applied, as old key and new key.
    pub renamed: Vec<KeyRename>,
    /// The keys whose flags changed, with the old and the new flags.
    pub flag_changes: Vec<FlagChange>,
    /// Who activated the version.
    pub actor: ActorRef,
    /// When the version was activated.
    pub occurred_at: SystemTime,
}

catalogue_event!(GraphQlPermissionsCreated, "iam.graphql_permissions.created");

impl GraphQlPermissionsCreated {
    /// `specId`, `service`, `createdKeys`, `renamed` and `flagChanges`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        created_data(
            self.spec_id,
            &self.service,
            &self.created_keys,
            &self.renamed,
            &self.flag_changes,
        )
    }
}

/// An activation created REST catalogue keys, renamed some and changed some flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestPermissionsCreated {
    /// The id of the event.
    pub event_id: Uuid,
    /// The activated version.
    pub spec_id: SpecId,
    /// The service of the document.
    pub service: ServiceName,
    /// The keys the catalogue gained.
    pub created_keys: Vec<PermissionKey>,
    /// The renames applied, as old key and new key.
    pub renamed: Vec<KeyRename>,
    /// The keys whose flags changed, with the old and the new flags.
    pub flag_changes: Vec<FlagChange>,
    /// Who activated the version.
    pub actor: ActorRef,
    /// When the version was activated.
    pub occurred_at: SystemTime,
}

catalogue_event!(RestPermissionsCreated, "iam.rest_permissions.created");

impl RestPermissionsCreated {
    /// `specId`, `service`, `createdKeys`, `renamed` and `flagChanges`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        created_data(
            self.spec_id,
            &self.service,
            &self.created_keys,
            &self.renamed,
            &self.flag_changes,
        )
    }
}

/// An activation or a retirement orphaned grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionsOrphaned {
    /// The id of the event.
    pub event_id: Uuid,
    /// The version whose activation or retirement orphaned the grants.
    pub spec_id: SpecId,
    /// The service of the version.
    pub service: ServiceName,
    /// The keys that lost grants.
    pub orphaned_keys: Vec<PermissionKey>,
    /// The roles that lost grants.
    pub affected_role_ids: Vec<RoleId>,
    /// Who activated or retired the version.
    pub actor: ActorRef,
    /// When the version was activated or retired.
    pub occurred_at: SystemTime,
}

catalogue_event!(PermissionsOrphaned, "iam.permissions.orphaned");

impl PermissionsOrphaned {
    /// `specId`, `service`, `orphanedKeys` and `affectedRoleIds`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        EventData::new()
            .with("specId", text(&self.spec_id))?
            .with("service", text(&self.service))?
            .with("orphanedKeys", texts(&self.orphaned_keys))?
            .with("affectedRoleIds", texts(&self.affected_role_ids))
    }
}

/// The `data` of both `…PermissionsCreated` events.
fn created_data(
    spec_id: SpecId,
    service: &ServiceName,
    created_keys: &[PermissionKey],
    renamed: &[KeyRename],
    flag_changes: &[FlagChange],
) -> Result<EventData, InvalidEventEnvelope> {
    EventData::new()
        .with("specId", text(&spec_id))?
        .with("service", text(service))?
        .with("createdKeys", texts(created_keys))?
        .with("renamed", rename_values(renamed)?)?
        .with("flagChanges", flag_change_values(flag_changes)?)
}

/// `{from, to}` per rename.
fn rename_values(renamed: &[KeyRename]) -> Result<EventValue, InvalidEventEnvelope> {
    renamed
        .iter()
        .map(|rename| {
            EventData::new()
                .with("from", text(&rename.from))?
                .with("to", text(&rename.to))
                .map(EventValue::Object)
        })
        .collect::<Result<Vec<_>, _>>()
        .map(EventValue::List)
}

/// `{key, before, after}` per flag change, the flags as `{sensitive, auditAlways}`.
fn flag_change_values(changes: &[FlagChange]) -> Result<EventValue, InvalidEventEnvelope> {
    changes
        .iter()
        .map(|change| {
            EventData::new()
                .with("key", text(&change.key))?
                .with("before", flag_value(change.before)?)?
                .with("after", flag_value(change.after)?)
                .map(EventValue::Object)
        })
        .collect::<Result<Vec<_>, _>>()
        .map(EventValue::List)
}

fn flag_value(flags: PermissionFlags) -> Result<EventValue, InvalidEventEnvelope> {
    EventData::new()
        .with("sensitive", EventValue::Bool(flags.is_sensitive()))?
        .with("auditAlways", EventValue::Bool(flags.is_audit_always()))
        .map(EventValue::Object)
}

/// The text form of a value.
fn text(value: &impl std::fmt::Display) -> EventValue {
    EventValue::Text(value.to_string())
}

/// The text forms of the values, as a list.
fn texts(values: &[impl std::fmt::Display]) -> EventValue {
    EventValue::List(values.iter().map(text).collect())
}

#[cfg(test)]
mod tests;
