//! The `Route` aggregate: one host, a set of methods and a path pattern that the gateway forwards
//! to an upstream (FR-56, FR-57).

pub mod cors;
pub mod event;
pub mod fields;
pub mod settings;
pub mod statement;

#[cfg(test)]
pub(crate) mod fixtures;

use std::time::SystemTime;

use shared_domain::{AggregateRoot, RecordedEvents, Uuid};

use crate::entity::aggregate_event::{Enveloper, envelope_as, envelopes_of};
use crate::entity::event_envelope::EventEnvelope;
use crate::error::{ConfigChangeRefused, InvalidEventEnvelope};
use crate::policy::route_revocation_rule::{RouteChangeClass, RouteRevocationRule};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::identifier::RouteId;
use event::{RouteCreated, RouteDeleted, RouteUpdated};
use fields::RouteFields;

/// Who changes a route, when (from the `Clock` port) and the id of the event that records it (from
/// the `UuidGenerator` port).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteStamp {
    /// The id of the recorded event.
    pub event_id: Uuid,
    /// Who causes the change.
    pub actor: ActorRef,
    /// When the change happens.
    pub occurred_at: SystemTime,
}

/// The stored state of a route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteParts {
    /// The identifier.
    pub id: RouteId,
    /// The configuration.
    pub fields: RouteFields,
    /// Whether IAM manages the route; the API refuses every change of a system route.
    pub system: bool,
    /// The optimistic-concurrency version.
    pub version: EntityVersion,
    /// When the route was created.
    pub created_at: SystemTime,
    /// When the route was last changed.
    pub updated_at: SystemTime,
    /// When the route was deleted; a deleted route refuses every change.
    pub deleted_at: Option<SystemTime>,
}

/// A route, versioned for optimistic concurrency. Every change checks the expected version and
/// records one event.
#[derive(Debug)]
pub struct Route {
    parts: RouteParts,
    events: RecordedEvents,
}

impl Route {
    /// Builds a new route at version 1 and records [`RouteCreated`].
    #[must_use]
    pub fn create(id: RouteId, fields: RouteFields, system: bool, stamp: RouteStamp) -> Self {
        let mut route = Self::restore(RouteParts {
            id,
            fields,
            system,
            version: EntityVersion::INITIAL,
            created_at: stamp.occurred_at,
            updated_at: stamp.occurred_at,
            deleted_at: None,
        });
        route.events.record(RouteCreated {
            event_id: stamp.event_id,
            route_id: id,
            version: EntityVersion::INITIAL,
            host: route.parts.fields.host.clone(),
            path_pattern: route.parts.fields.path_pattern.clone(),
            service: route.parts.fields.service.clone(),
            actor: stamp.actor,
            occurred_at: stamp.occurred_at,
        });
        route
    }

    /// Rebuilds a stored route; records nothing.
    #[must_use]
    pub fn restore(parts: RouteParts) -> Self {
        Self {
            parts,
            events: RecordedEvents::default(),
        }
    }

    /// The state of the route.
    #[must_use]
    pub const fn parts(&self) -> &RouteParts {
        &self.parts
    }

    /// Replaces the configuration and records [`RouteUpdated`]; the class of the change says
    /// whether it takes access away.
    ///
    /// # Errors
    ///
    /// [`ConfigChangeRefused::Deleted`] for a deleted route, [`ConfigChangeRefused::Version`] when
    /// `expected` is missing or stale and [`ConfigChangeRefused::Range`] when the version cannot
    /// be increased; nothing changes then.
    pub fn update(
        &mut self,
        expected: Option<EntityVersion>,
        fields: RouteFields,
        stamp: RouteStamp,
    ) -> Result<RouteChangeClass, ConfigChangeRefused> {
        let version = self.next_version(expected)?;
        let class = RouteRevocationRule::classify_update(&self.parts.fields, &fields);
        let changed_fields = self.parts.fields.changed_fields(&fields);
        self.parts.fields = fields;
        self.advance(version, stamp.occurred_at);
        self.events.record(RouteUpdated {
            event_id: stamp.event_id,
            route_id: self.parts.id,
            version,
            host: self.parts.fields.host.clone(),
            path_pattern: self.parts.fields.path_pattern.clone(),
            changed_fields,
            revocation: class == RouteChangeClass::Revocation,
            actor: stamp.actor,
            occurred_at: stamp.occurred_at,
        });
        Ok(class)
    }

    /// Marks the route deleted and records [`RouteDeleted`].
    ///
    /// # Errors
    ///
    /// The errors of [`Route::update`]; nothing changes then.
    pub fn delete(
        &mut self,
        expected: Option<EntityVersion>,
        stamp: RouteStamp,
    ) -> Result<(), ConfigChangeRefused> {
        let version = self.next_version(expected)?;
        self.advance(version, stamp.occurred_at);
        self.parts.deleted_at = Some(stamp.occurred_at);
        self.events.record(RouteDeleted {
            event_id: stamp.event_id,
            route_id: self.parts.id,
            version,
            host: self.parts.fields.host.clone(),
            path_pattern: self.parts.fields.path_pattern.clone(),
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

    /// The version after a change, once the route is known to exist and `expected` is current.
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

impl AggregateRoot for Route {
    fn recorded_events(&mut self) -> &mut RecordedEvents {
        &mut self.events
    }
}

/// The three events of a route, each with its way to an envelope.
const ENVELOPERS: [Enveloper; 3] = [
    envelope_as::<RouteCreated>,
    envelope_as::<RouteUpdated>,
    envelope_as::<RouteDeleted>,
];

#[cfg(test)]
mod tests;
