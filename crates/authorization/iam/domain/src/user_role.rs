//! The `UserRole` aggregate (board name `UserRole`): the assignment of a role to a subject at a
//! scope, with an optional expiry (FR-26 to FR-29).

pub mod event;
pub mod statement;

use std::any::Any;
use std::time::SystemTime;

use shared_domain::{AggregateRoot, DomainEvent, RecordedEvents, Uuid};

use crate::entity::event_envelope::{EventEnvelope, IamDomainEvent};
use crate::error::{InvalidEventEnvelope, InvalidUserRole, UserRoleChangeRefused};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::assignment_expiry::AssignmentExpiry;
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::identifier::{RoleId, UserRoleId};
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::role_name::RoleName;
use crate::value_object::subject::SubjectRef;
use event::{
    AssignedRole, PrivilegedRoleAssigned, UserRoleAssigned, UserRoleRevoked, UserRoleUpdated,
};

/// Who changes an assignment, when (from the `Clock` port) and the id of the event that records it
/// (from the `UuidGenerator` port).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRoleStamp {
    /// The id of the recorded event.
    pub event_id: Uuid,
    /// Who causes the change.
    pub actor: ActorRef,
    /// When the change happens.
    pub occurred_at: SystemTime,
}

/// The privileged grants of an assigned role and the id of the security alert that records them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegedGrants {
    /// The id of the recorded [`PrivilegedRoleAssigned`] event.
    pub event_id: Uuid,
    /// The wildcards and reserved keys the role grants, in order.
    pub keys: Vec<PermissionGrant>,
}

/// What a new assignment holds, before its expiry is checked against the `Clock` port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRoleAssignment {
    /// The identifier of the assignment.
    pub id: UserRoleId,
    /// Who receives the role.
    pub subject: SubjectRef,
    /// The assigned role.
    pub role_id: RoleId,
    /// The name of the assigned role, for the events.
    pub role_name: RoleName,
    /// Where the role applies.
    pub scope: AssignmentScope,
    /// When the assignment expires; `None` for an assignment that never expires.
    pub expires_at: Option<SystemTime>,
    /// The privileged grants of the role; `None` when it holds no wildcard and no reserved key.
    pub privileged: Option<PrivilegedGrants>,
}

/// Why an assignment was revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RevocationCause {
    /// An administrator revoked the assignment (FR-29).
    Revoked,
    /// The assigned role was deleted (FR-23).
    RoleDeleted,
    /// The User service reported the user deleted (FR-18).
    UserDeleted,
}

impl RevocationCause {
    /// The text form: `revoked`, `role_deleted` or `user_deleted`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Revoked => "revoked",
            Self::RoleDeleted => "role_deleted",
            Self::UserDeleted => "user_deleted",
        }
    }
}

/// The stored state of an assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRoleParts {
    /// The identifier.
    pub id: UserRoleId,
    /// Who holds the role.
    pub subject: SubjectRef,
    /// The assigned role.
    pub role_id: RoleId,
    /// Where the role applies.
    pub scope: AssignmentScope,
    /// When the assignment expires; `None` for an assignment that never expires.
    pub expires_at: Option<AssignmentExpiry>,
    /// The optimistic-concurrency version.
    pub version: EntityVersion,
    /// Who created the assignment.
    pub created_by: ActorRef,
    /// When the assignment was created.
    pub created_at: SystemTime,
    /// When the assignment was last changed.
    pub updated_at: SystemTime,
    /// When the assignment was revoked; a revoked assignment grants nothing and refuses changes.
    pub revoked_at: Option<SystemTime>,
}

impl UserRoleParts {
    /// Whether the assignment is revoked.
    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Whether the assignment grants its role at `now`: it is not revoked and has not expired.
    #[must_use]
    pub fn is_active_at(&self, now: SystemTime) -> bool {
        !self.is_revoked() && self.expires_at.is_none_or(|expiry| !expiry.has_passed(now))
    }

    /// Whether both assignments are not revoked and give the same role to the same subject at the
    /// same scope.
    ///
    /// The triple is unique among assignments that are not revoked, so the second one is a
    /// duplicate. An expired assignment still holds its triple until it is revoked.
    #[must_use]
    pub fn duplicates(&self, other: &Self) -> bool {
        !self.is_revoked()
            && !other.is_revoked()
            && self.subject == other.subject
            && self.role_id == other.role_id
            && self.scope == other.scope
    }
}

/// An assignment of a role to a subject at a scope, versioned for optimistic concurrency. Every
/// change checks the expected version and records one event.
#[derive(Debug)]
pub struct UserRole {
    parts: UserRoleParts,
    events: RecordedEvents,
}

impl UserRole {
    /// Builds a new assignment at version 1 and records [`UserRoleAssigned`], followed by
    /// [`PrivilegedRoleAssigned`] when the role holds privileged grants.
    ///
    /// # Errors
    ///
    /// [`InvalidUserRole::ExpiryNotInFuture`] when the expiry is not later than the time of the
    /// stamp.
    pub fn assign(
        assignment: UserRoleAssignment,
        stamp: UserRoleStamp,
    ) -> Result<Self, InvalidUserRole> {
        let expires_at = expiry(assignment.expires_at, stamp.occurred_at)?;
        let mut user_role = Self::restore(UserRoleParts {
            id: assignment.id,
            subject: assignment.subject.clone(),
            role_id: assignment.role_id,
            scope: assignment.scope,
            expires_at,
            version: EntityVersion::INITIAL,
            created_by: stamp.actor.clone(),
            created_at: stamp.occurred_at,
            updated_at: stamp.occurred_at,
            revoked_at: None,
        });
        let role = AssignedRole {
            subject: assignment.subject,
            role_id: assignment.role_id,
            role_name: assignment.role_name,
            scope: assignment.scope,
        };
        user_role.events.record(UserRoleAssigned {
            event_id: stamp.event_id,
            user_role_id: assignment.id,
            version: EntityVersion::INITIAL,
            role: role.clone(),
            expires_at,
            actor: stamp.actor.clone(),
            occurred_at: stamp.occurred_at,
        });
        if let Some(privileged) = assignment.privileged {
            user_role.events.record(PrivilegedRoleAssigned {
                event_id: privileged.event_id,
                user_role_id: assignment.id,
                version: EntityVersion::INITIAL,
                role,
                expires_at,
                privileged_keys: privileged.keys,
                actor: stamp.actor,
                occurred_at: stamp.occurred_at,
            });
        }
        Ok(user_role)
    }

    /// Rebuilds a stored assignment; records nothing.
    #[must_use]
    pub fn restore(parts: UserRoleParts) -> Self {
        Self {
            parts,
            events: RecordedEvents::default(),
        }
    }

    /// The state of the assignment.
    #[must_use]
    pub const fn parts(&self) -> &UserRoleParts {
        &self.parts
    }

    /// Sets, extends, shortens or clears the expiry and records [`UserRoleUpdated`].
    ///
    /// # Errors
    ///
    /// [`UserRoleChangeRefused::Revoked`] for a revoked assignment,
    /// [`UserRoleChangeRefused::Version`] when `expected` is missing or stale,
    /// [`UserRoleChangeRefused::Range`] when the version cannot be increased and
    /// [`UserRoleChangeRefused::Invalid`] when the expiry is not later than the time of the stamp;
    /// nothing changes then.
    pub fn change_expiry(
        &mut self,
        expected: Option<EntityVersion>,
        expires_at: Option<SystemTime>,
        stamp: UserRoleStamp,
    ) -> Result<(), UserRoleChangeRefused> {
        let version = self.next_version(expected)?;
        let expires_at = expiry(expires_at, stamp.occurred_at)?;
        self.parts.expires_at = expires_at;
        self.advance(version, stamp.occurred_at);
        self.events.record(UserRoleUpdated {
            event_id: stamp.event_id,
            user_role_id: self.parts.id,
            version,
            subject: self.parts.subject.clone(),
            expires_at,
            actor: stamp.actor,
            occurred_at: stamp.occurred_at,
        });
        Ok(())
    }

    /// Marks the assignment revoked and records [`UserRoleRevoked`] with the name of the role and
    /// the cause.
    ///
    /// # Errors
    ///
    /// [`UserRoleChangeRefused::Revoked`] for a revoked assignment,
    /// [`UserRoleChangeRefused::Version`] when `expected` is missing or stale and
    /// [`UserRoleChangeRefused::Range`] when the version cannot be increased; nothing changes then.
    pub fn revoke(
        &mut self,
        expected: Option<EntityVersion>,
        role_name: RoleName,
        cause: RevocationCause,
        stamp: UserRoleStamp,
    ) -> Result<(), UserRoleChangeRefused> {
        let version = self.next_version(expected)?;
        self.advance(version, stamp.occurred_at);
        self.parts.revoked_at = Some(stamp.occurred_at);
        self.events.record(UserRoleRevoked {
            event_id: stamp.event_id,
            user_role_id: self.parts.id,
            version,
            role: AssignedRole {
                subject: self.parts.subject.clone(),
                role_id: self.parts.role_id,
                role_name,
                scope: self.parts.scope,
            },
            cause,
            actor: stamp.actor,
            occurred_at: stamp.occurred_at,
        });
        Ok(())
    }

    /// Drains the recorded events as envelopes of `iam.events.v1`, in recording order, for the
    /// change that commits them.
    ///
    /// # Errors
    ///
    /// The [`InvalidEventEnvelope`] of the first event that cannot be enveloped:
    /// [`InvalidEventEnvelope::EventType`] for an event that is not one of the four events of an
    /// assignment, which an assignment never records itself.
    pub fn pull_envelopes(&mut self) -> Result<Vec<EventEnvelope>, InvalidEventEnvelope> {
        self.pull_domain_events()
            .iter()
            .map(|event| envelope_of(event.as_ref()))
            .collect()
    }

    /// The version after a change, once the assignment is known not to be revoked and `expected`
    /// is current.
    fn next_version(
        &self,
        expected: Option<EntityVersion>,
    ) -> Result<EntityVersion, UserRoleChangeRefused> {
        if self.parts.is_revoked() {
            return Err(UserRoleChangeRefused::Revoked);
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

impl AggregateRoot for UserRole {
    fn recorded_events(&mut self) -> &mut RecordedEvents {
        &mut self.events
    }
}

/// The envelope of an event of one type, when the event has that type.
type Enveloper = fn(&dyn Any) -> Option<Result<EventEnvelope, InvalidEventEnvelope>>;

/// The envelope of `event` when it is an `E`.
fn envelope_as<E: IamDomainEvent>(
    event: &dyn Any,
) -> Option<Result<EventEnvelope, InvalidEventEnvelope>> {
    event
        .downcast_ref::<E>()
        .map(|event| EventEnvelope::of(event))
}

/// The four events of an assignment, each with its way to an envelope.
const ENVELOPERS: [Enveloper; 4] = [
    envelope_as::<UserRoleAssigned>,
    envelope_as::<PrivilegedRoleAssigned>,
    envelope_as::<UserRoleUpdated>,
    envelope_as::<UserRoleRevoked>,
];

/// The envelope of one of the four events of an assignment.
fn envelope_of(event: &dyn DomainEvent) -> Result<EventEnvelope, InvalidEventEnvelope> {
    let event: &dyn Any = event;
    ENVELOPERS
        .iter()
        .find_map(|enveloper| enveloper(event))
        .unwrap_or(Err(InvalidEventEnvelope::EventType))
}

/// The expiry of a write at `now`; `None` keeps the assignment without an expiry.
fn expiry(
    at: Option<SystemTime>,
    now: SystemTime,
) -> Result<Option<AssignmentExpiry>, InvalidUserRole> {
    at.map(|at| AssignmentExpiry::new(at, now)).transpose()
}

#[cfg(test)]
mod tests;
