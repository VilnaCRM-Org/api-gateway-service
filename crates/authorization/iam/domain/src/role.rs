//! The `Role` aggregate (board name `Role`): a named set of permission grants (FR-20 to FR-24).

pub mod event;

use std::time::SystemTime;

use shared_domain::{AggregateRoot, RecordedEvents, Uuid};

use crate::error::{InvalidRole, RoleChangeRefused};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::identifier::RoleId;
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::permission_grant_set::PermissionGrantSet;
use crate::value_object::role_description::RoleDescription;
use crate::value_object::role_kind::RoleKind;
use crate::value_object::role_name::RoleName;
use event::{RoleCreated, RoleDeleted, RolePermissionsChanged, RoleUpdated};

/// The validated name and description of a new role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleFields {
    name: RoleName,
    description: Option<RoleDescription>,
}

impl RoleFields {
    /// Validates the name and the optional description together.
    ///
    /// # Errors
    ///
    /// Every violation, in the order name then description: the [`InvalidRole`] of
    /// [`RoleName::new`] and of [`RoleDescription::new`].
    pub fn new(name: String, description: Option<String>) -> Result<Self, Vec<InvalidRole>> {
        let name = RoleName::new(name);
        let description = description.map(RoleDescription::new).transpose();
        match (name, description) {
            (Ok(name), Ok(description)) => Ok(Self { name, description }),
            (name, description) => Err(name.err().into_iter().chain(description.err()).collect()),
        }
    }

    /// The name.
    #[must_use]
    pub const fn name(&self) -> &RoleName {
        &self.name
    }

    /// The description, when one was given.
    #[must_use]
    pub const fn description(&self) -> Option<&RoleDescription> {
        self.description.as_ref()
    }
}

/// What an update does with the description.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RoleDescriptionChange {
    /// Keeps the stored description.
    #[default]
    Keep,
    /// Removes the description.
    Remove,
    /// Replaces the description.
    Set(RoleDescription),
}

impl RoleDescriptionChange {
    /// Applies the change to `description`; whether it was replaced or removed.
    fn apply(self, description: &mut Option<RoleDescription>) -> bool {
        match self {
            Self::Keep => return false,
            Self::Remove => *description = None,
            Self::Set(value) => *description = Some(value),
        }
        true
    }
}

/// The changes of an update: a name that is `Some` replaces the stored one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RolePatch {
    /// The new name.
    pub name: Option<RoleName>,
    /// What happens to the description.
    pub description: RoleDescriptionChange,
}

/// Who changes a role, when (from the `Clock` port) and the id of the event that records it (from
/// the `UuidGenerator` port).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleStamp {
    /// The id of the recorded event.
    pub event_id: Uuid,
    /// Who causes the change.
    pub actor: ActorRef,
    /// When the change happens.
    pub occurred_at: SystemTime,
}

/// The stored state of a role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleParts {
    /// The identifier.
    pub id: RoleId,
    /// The name.
    pub name: RoleName,
    /// The optional description.
    pub description: Option<RoleDescription>,
    /// Whether IAM or an administrator manages the role.
    pub kind: RoleKind,
    /// The grants.
    pub grants: PermissionGrantSet,
    /// The optimistic-concurrency version.
    pub version: EntityVersion,
    /// When the role was created.
    pub created_at: SystemTime,
    /// When the role was last changed.
    pub updated_at: SystemTime,
    /// When the role was deleted; a deleted role refuses every change.
    pub deleted_at: Option<SystemTime>,
}

/// A role: a name, an optional description, a kind and a set of grants, versioned for optimistic
/// concurrency. Every change checks the expected version and records one event.
#[derive(Debug)]
pub struct Role {
    parts: RoleParts,
    events: RecordedEvents,
}

impl Role {
    /// Builds a new custom role without grants at version 1 and records [`RoleCreated`].
    #[must_use]
    pub fn create(id: RoleId, fields: RoleFields, stamp: RoleStamp) -> Self {
        let mut role = Self::restore(RoleParts {
            id,
            name: fields.name,
            description: fields.description,
            kind: RoleKind::Custom,
            grants: PermissionGrantSet::default(),
            version: EntityVersion::INITIAL,
            created_at: stamp.occurred_at,
            updated_at: stamp.occurred_at,
            deleted_at: None,
        });
        role.events.record(RoleCreated {
            event_id: stamp.event_id,
            role_id: id,
            version: EntityVersion::INITIAL,
            name: role.parts.name.clone(),
            kind: RoleKind::Custom,
            actor: stamp.actor,
            occurred_at: stamp.occurred_at,
        });
        role
    }

    /// Rebuilds a stored role; records nothing.
    #[must_use]
    pub fn restore(parts: RoleParts) -> Self {
        Self {
            parts,
            events: RecordedEvents::default(),
        }
    }

    /// The state of the role.
    #[must_use]
    pub const fn parts(&self) -> &RoleParts {
        &self.parts
    }

    /// Changes the name and the description and records [`RoleUpdated`].
    ///
    /// # Errors
    ///
    /// [`RoleChangeRefused::SystemRole`] for a system role, [`RoleChangeRefused::Deleted`] for a
    /// deleted role, [`RoleChangeRefused::Version`] when `expected` is missing or stale and
    /// [`RoleChangeRefused::Invalid`] when the version cannot be increased; nothing changes then.
    pub fn update(
        &mut self,
        expected: Option<EntityVersion>,
        patch: RolePatch,
        stamp: RoleStamp,
    ) -> Result<(), RoleChangeRefused> {
        let version = self.next_custom_version(expected)?;
        let mut changed_fields = Vec::new();
        if let Some(name) = patch.name.clone() {
            self.parts.name = name;
            changed_fields.push(RoleUpdated::NAME_FIELD);
        }
        if patch.description.apply(&mut self.parts.description) {
            changed_fields.push(RoleUpdated::DESCRIPTION_FIELD);
        }
        self.advance(version, stamp.occurred_at);
        self.events.record(RoleUpdated {
            event_id: stamp.event_id,
            role_id: self.parts.id,
            version,
            name: patch.name,
            changed_fields,
            actor: stamp.actor,
            occurred_at: stamp.occurred_at,
        });
        Ok(())
    }

    /// Marks the role deleted and records [`RoleDeleted`] with the number of assignments that the
    /// deletion revokes.
    ///
    /// # Errors
    ///
    /// The errors of [`Role::update`]; nothing changes then.
    pub fn delete(
        &mut self,
        expected: Option<EntityVersion>,
        revoked_assignments: u32,
        stamp: RoleStamp,
    ) -> Result<(), RoleChangeRefused> {
        let version = self.next_custom_version(expected)?;
        self.advance(version, stamp.occurred_at);
        self.parts.deleted_at = Some(stamp.occurred_at);
        self.events.record(RoleDeleted {
            event_id: stamp.event_id,
            role_id: self.parts.id,
            version,
            name: self.parts.name.clone(),
            revoked_assignments,
            actor: stamp.actor,
            occurred_at: stamp.occurred_at,
        });
        Ok(())
    }

    /// Replaces the full grant set and records [`RolePermissionsChanged`] with the added and the
    /// removed grants. System roles accept it: the bootstrap seeds their grants this way.
    ///
    /// # Errors
    ///
    /// [`RoleChangeRefused::Deleted`] for a deleted role, [`RoleChangeRefused::Version`] when
    /// `expected` is missing or stale and [`RoleChangeRefused::Invalid`] when the version cannot
    /// be increased; nothing changes then.
    pub fn replace_permissions(
        &mut self,
        expected: Option<EntityVersion>,
        grants: PermissionGrantSet,
        stamp: RoleStamp,
    ) -> Result<(), RoleChangeRefused> {
        let version = self.next_version(expected)?;
        let added = difference(&grants, &self.parts.grants);
        let removed = difference(&self.parts.grants, &grants);
        self.parts.grants = grants;
        self.advance(version, stamp.occurred_at);
        self.events.record(RolePermissionsChanged {
            event_id: stamp.event_id,
            role_id: self.parts.id,
            version,
            added,
            removed,
            actor: stamp.actor,
            occurred_at: stamp.occurred_at,
        });
        Ok(())
    }

    /// The version after a change that a system role refuses.
    fn next_custom_version(
        &self,
        expected: Option<EntityVersion>,
    ) -> Result<EntityVersion, RoleChangeRefused> {
        if self.parts.kind == RoleKind::System {
            return Err(RoleChangeRefused::SystemRole);
        }
        self.next_version(expected)
    }

    /// The version after a change, once the role is known to exist and `expected` is current.
    fn next_version(
        &self,
        expected: Option<EntityVersion>,
    ) -> Result<EntityVersion, RoleChangeRefused> {
        if self.parts.deleted_at.is_some() {
            return Err(RoleChangeRefused::Deleted);
        }
        self.parts.version.check(expected)?;
        Ok(self.parts.version.next()?)
    }

    /// Stores the version and the time of a change.
    const fn advance(&mut self, version: EntityVersion, at: SystemTime) {
        self.parts.version = version;
        self.parts.updated_at = at;
    }
}

impl AggregateRoot for Role {
    fn recorded_events(&mut self) -> &mut RecordedEvents {
        &mut self.events
    }
}

/// The grants of `left` that `right` does not hold, in order.
fn difference(left: &PermissionGrantSet, right: &PermissionGrantSet) -> Vec<PermissionGrant> {
    left.iter()
        .filter(|grant| !right.contains(grant))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests;
