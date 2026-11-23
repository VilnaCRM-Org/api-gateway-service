//! The `RatePolicy` aggregate: how many requests a key may send in a period (FR-56).

pub mod event;
pub mod fields;
pub mod statement;

use std::time::SystemTime;

use shared_domain::{AggregateRoot, RecordedEvents, Uuid};

use crate::entity::aggregate_event::{Enveloper, envelope_as, envelopes_of};
use crate::entity::event_envelope::EventEnvelope;
use crate::error::{ConfigChangeRefused, InvalidEventEnvelope};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::identifier::RatePolicyId;
use event::{RatePolicyCreated, RatePolicyDeleted, RatePolicyUpdated};
use fields::RatePolicyFields;

/// Who changes a rate policy, when (from the `Clock` port) and the id of the event that records it
/// (from the `UuidGenerator` port).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatePolicyStamp {
    /// The id of the recorded event.
    pub event_id: Uuid,
    /// Who causes the change.
    pub actor: ActorRef,
    /// When the change happens.
    pub occurred_at: SystemTime,
}

/// The stored state of a rate policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatePolicyParts {
    /// The identifier.
    pub id: RatePolicyId,
    /// The configuration.
    pub fields: RatePolicyFields,
    /// The optimistic-concurrency version.
    pub version: EntityVersion,
    /// When the policy was created.
    pub created_at: SystemTime,
    /// When the policy was last changed.
    pub updated_at: SystemTime,
    /// When the policy was deleted; a deleted policy refuses every change.
    pub deleted_at: Option<SystemTime>,
}

/// A rate policy, versioned for optimistic concurrency. Every change checks the expected version
/// and records one event.
#[derive(Debug)]
pub struct RatePolicy {
    parts: RatePolicyParts,
    events: RecordedEvents,
}

impl RatePolicy {
    /// Builds a new rate policy at version 1 and records [`RatePolicyCreated`].
    #[must_use]
    pub fn create(id: RatePolicyId, fields: RatePolicyFields, stamp: RatePolicyStamp) -> Self {
        let mut policy = Self::restore(RatePolicyParts {
            id,
            fields,
            version: EntityVersion::INITIAL,
            created_at: stamp.occurred_at,
            updated_at: stamp.occurred_at,
            deleted_at: None,
        });
        policy.events.record(RatePolicyCreated {
            event_id: stamp.event_id,
            rate_policy_id: id,
            version: EntityVersion::INITIAL,
            name: policy.parts.fields.name().to_owned(),
            actor: stamp.actor,
            occurred_at: stamp.occurred_at,
        });
        policy
    }

    /// Rebuilds a stored rate policy; records nothing.
    #[must_use]
    pub fn restore(parts: RatePolicyParts) -> Self {
        Self {
            parts,
            events: RecordedEvents::default(),
        }
    }

    /// The state of the rate policy.
    #[must_use]
    pub const fn parts(&self) -> &RatePolicyParts {
        &self.parts
    }

    /// Replaces the configuration and records [`RatePolicyUpdated`].
    ///
    /// # Errors
    ///
    /// [`ConfigChangeRefused::Deleted`] for a deleted policy, [`ConfigChangeRefused::Version`]
    /// when `expected` is missing or stale and [`ConfigChangeRefused::Range`] when the version
    /// cannot be increased; nothing changes then.
    pub fn update(
        &mut self,
        expected: Option<EntityVersion>,
        fields: RatePolicyFields,
        stamp: RatePolicyStamp,
    ) -> Result<(), ConfigChangeRefused> {
        let version = self.next_version(expected)?;
        let changed_fields = self.parts.fields.changed_fields(&fields);
        self.parts.fields = fields;
        self.advance(version, stamp.occurred_at);
        self.events.record(RatePolicyUpdated {
            event_id: stamp.event_id,
            rate_policy_id: self.parts.id,
            version,
            name: self.parts.fields.name().to_owned(),
            changed_fields,
            actor: stamp.actor,
            occurred_at: stamp.occurred_at,
        });
        Ok(())
    }

    /// Marks the rate policy deleted and records [`RatePolicyDeleted`]. The application first
    /// checks that no route references the policy.
    ///
    /// # Errors
    ///
    /// The errors of [`RatePolicy::update`]; nothing changes then.
    pub fn delete(
        &mut self,
        expected: Option<EntityVersion>,
        stamp: RatePolicyStamp,
    ) -> Result<(), ConfigChangeRefused> {
        let version = self.next_version(expected)?;
        self.advance(version, stamp.occurred_at);
        self.parts.deleted_at = Some(stamp.occurred_at);
        self.events.record(RatePolicyDeleted {
            event_id: stamp.event_id,
            rate_policy_id: self.parts.id,
            version,
            name: self.parts.fields.name().to_owned(),
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

    /// The version after a change, once the policy is known to exist and `expected` is current.
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

impl AggregateRoot for RatePolicy {
    fn recorded_events(&mut self) -> &mut RecordedEvents {
        &mut self.events
    }
}

/// The three events of a rate policy, each with its way to an envelope.
const ENVELOPERS: [Enveloper; 3] = [
    envelope_as::<RatePolicyCreated>,
    envelope_as::<RatePolicyUpdated>,
    envelope_as::<RatePolicyDeleted>,
];

#[cfg(test)]
mod tests;
