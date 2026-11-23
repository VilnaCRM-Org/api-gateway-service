//! The `Upstream` aggregate: a Kubernetes Service that the gateway proxies to, serving one
//! catalogue service (FR-56).

pub mod event;
pub mod settings;

use std::time::SystemTime;

use shared_domain::{AggregateRoot, RecordedEvents, Uuid};

use crate::entity::aggregate_event::{Enveloper, envelope_as, envelopes_of};
use crate::entity::event_envelope::EventEnvelope;
use crate::error::{ConfigChangeRefused, InvalidEventEnvelope, UpstreamChangeRefused};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::identifier::UpstreamId;
use crate::value_object::upstream_name::UpstreamName;
use event::{UpstreamCreated, UpstreamDeleted, UpstreamUpdated};
use settings::{UpstreamFields, UpstreamSettings};

/// Who changes an upstream, when (from the `Clock` port) and the id of the event that records it
/// (from the `UuidGenerator` port).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamStamp {
    /// The id of the recorded event.
    pub event_id: Uuid,
    /// Who causes the change.
    pub actor: ActorRef,
    /// When the change happens.
    pub occurred_at: SystemTime,
}

/// The stored state of an upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamParts {
    /// The identifier.
    pub id: UpstreamId,
    /// The name; immutable after creation.
    pub name: UpstreamName,
    /// The settings.
    pub settings: UpstreamSettings,
    /// Whether IAM manages the upstream; the API refuses every change of a system upstream.
    pub system: bool,
    /// The optimistic-concurrency version.
    pub version: EntityVersion,
    /// When the upstream was created.
    pub created_at: SystemTime,
    /// When the upstream was last changed.
    pub updated_at: SystemTime,
    /// When the upstream was deleted; a deleted upstream refuses every change.
    pub deleted_at: Option<SystemTime>,
}

/// An upstream, versioned for optimistic concurrency. Every change checks the expected version
/// and records one event.
#[derive(Debug)]
pub struct Upstream {
    parts: UpstreamParts,
    events: RecordedEvents,
}

impl Upstream {
    /// Builds a new upstream at version 1 and records [`UpstreamCreated`].
    #[must_use]
    pub fn create(
        id: UpstreamId,
        fields: UpstreamFields,
        system: bool,
        stamp: UpstreamStamp,
    ) -> Self {
        let (name, settings) = fields.into_parts();
        let mut upstream = Self::restore(UpstreamParts {
            id,
            name,
            settings,
            system,
            version: EntityVersion::INITIAL,
            created_at: stamp.occurred_at,
            updated_at: stamp.occurred_at,
            deleted_at: None,
        });
        upstream.events.record(UpstreamCreated {
            event_id: stamp.event_id,
            upstream_id: id,
            version: EntityVersion::INITIAL,
            name: upstream.parts.name.clone(),
            catalog_service: upstream.parts.settings.catalog_service().clone(),
            actor: stamp.actor,
            occurred_at: stamp.occurred_at,
        });
        upstream
    }

    /// Rebuilds a stored upstream; records nothing.
    #[must_use]
    pub fn restore(parts: UpstreamParts) -> Self {
        Self {
            parts,
            events: RecordedEvents::default(),
        }
    }

    /// The state of the upstream.
    #[must_use]
    pub const fn parts(&self) -> &UpstreamParts {
        &self.parts
    }

    /// Replaces the settings and records [`UpstreamUpdated`].
    ///
    /// # Errors
    ///
    /// [`UpstreamChangeRefused::Renamed`] when `fields` names another name than the stored one,
    /// and [`UpstreamChangeRefused::Refused`] for a deleted upstream, a missing or stale
    /// `expected` version or a version that cannot be increased; nothing changes then.
    pub fn update(
        &mut self,
        expected: Option<EntityVersion>,
        fields: UpstreamFields,
        stamp: UpstreamStamp,
    ) -> Result<(), UpstreamChangeRefused> {
        let version = self.next_version(expected)?;
        if fields.name() != &self.parts.name {
            return Err(UpstreamChangeRefused::Renamed);
        }
        let (_name, settings) = fields.into_parts();
        let changed_fields = self.parts.settings.changed_fields(&settings);
        self.parts.settings = settings;
        self.advance(version, stamp.occurred_at);
        self.events.record(UpstreamUpdated {
            event_id: stamp.event_id,
            upstream_id: self.parts.id,
            version,
            name: self.parts.name.clone(),
            changed_fields,
            actor: stamp.actor,
            occurred_at: stamp.occurred_at,
        });
        Ok(())
    }

    /// Marks the upstream deleted and records [`UpstreamDeleted`]. The application first checks
    /// that no route references the upstream.
    ///
    /// # Errors
    ///
    /// [`ConfigChangeRefused::Deleted`] for a deleted upstream, [`ConfigChangeRefused::Version`]
    /// when `expected` is missing or stale and [`ConfigChangeRefused::Range`] when the version
    /// cannot be increased; nothing changes then.
    pub fn delete(
        &mut self,
        expected: Option<EntityVersion>,
        stamp: UpstreamStamp,
    ) -> Result<(), ConfigChangeRefused> {
        let version = self.next_version(expected)?;
        self.advance(version, stamp.occurred_at);
        self.parts.deleted_at = Some(stamp.occurred_at);
        self.events.record(UpstreamDeleted {
            event_id: stamp.event_id,
            upstream_id: self.parts.id,
            version,
            name: self.parts.name.clone(),
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
    /// The [`InvalidEventEnvelope`] of the first event that cannot be enveloped.
    pub fn pull_envelopes(&mut self) -> Result<Vec<EventEnvelope>, InvalidEventEnvelope> {
        envelopes_of(&self.pull_domain_events(), &ENVELOPERS)
    }

    /// The version after a change, once the upstream is known to exist and `expected` is current.
    fn next_version(
        &self,
        expected: Option<EntityVersion>,
    ) -> Result<EntityVersion, ConfigChangeRefused> {
        if self.parts.deleted_at.is_some() {
            return Err(ConfigChangeRefused::Deleted);
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

impl AggregateRoot for Upstream {
    fn recorded_events(&mut self) -> &mut RecordedEvents {
        &mut self.events
    }
}

/// The three events of an upstream, each with its way to an envelope.
const ENVELOPERS: [Enveloper; 3] = [
    envelope_as::<UpstreamCreated>,
    envelope_as::<UpstreamUpdated>,
    envelope_as::<UpstreamDeleted>,
];

#[cfg(test)]
mod tests;
