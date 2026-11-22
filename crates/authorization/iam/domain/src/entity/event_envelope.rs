//! The envelope of an event of `iam.events.v1` (FR-47).

use std::time::SystemTime;

use shared_domain::{DomainEvent, Uuid};

use crate::error::InvalidEventEnvelope;
use crate::micros;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::event_data::EventData;
use crate::value_object::event_type::EventType;

/// A domain event of IAM: a [`DomainEvent`] whose name is an [`EventType`] and that names the
/// actor, the resulting entity version and the fields of its `data`.
pub trait IamDomainEvent: DomainEvent {
    /// Who caused the event.
    fn actor(&self) -> &ActorRef;

    /// The version of the aggregate after the change, when the aggregate is versioned.
    fn entity_version(&self) -> Option<EntityVersion>;

    /// The fields of `data` beyond the common fields that the envelope writes itself.
    ///
    /// # Errors
    ///
    /// An [`InvalidEventEnvelope`] when a field breaks a rule of [`EventData`].
    fn data(&self) -> Result<EventData, InvalidEventEnvelope>;
}

/// The values of an envelope, as the recording code assembles them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventEnvelopeParts {
    /// The id of the event, a UUID v7 from the `UuidGenerator` port; consumers de-duplicate by it.
    pub id: Uuid,
    /// The type of the event.
    pub event_type: EventType,
    /// When the event happened, from the `Clock` port.
    pub occurred_at: SystemTime,
    /// The aggregate that recorded the event; also the Kafka record key.
    pub aggregate_id: Uuid,
    /// Who caused the event.
    pub actor: ActorRef,
    /// The version of the aggregate after the change.
    pub entity_version: Option<EntityVersion>,
    /// The fields of `data` beyond the common fields.
    pub data: EventData,
}

/// The envelope `{id, type, occurredAt, data}` of one event of `iam.events.v1`.
///
/// `data` holds the common fields `aggregateId`, `entityVersion`, `actor` and `policyVersion`,
/// which the envelope writes itself (the policy version is the one of the committing transaction),
/// then the event's own fields. The time is kept in whole microseconds. The encoded envelope must
/// not exceed [`EventEnvelope::MAX_ENCODED_BYTES`]; the encoder in the infrastructure layer checks
/// that bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventEnvelope {
    parts: EventEnvelopeParts,
    occurred_at_micros: i64,
}

impl EventEnvelope {
    /// The largest size of an encoded envelope: 64 KiB.
    pub const MAX_ENCODED_BYTES: usize = 65_536;

    /// The common fields of `data`, written by the envelope and refused among the event's own.
    pub const RESERVED_FIELDS: [&'static str; 4] =
        ["aggregateId", "entityVersion", "actor", "policyVersion"];

    /// Validates the values and truncates the time to whole microseconds.
    ///
    /// # Errors
    ///
    /// [`InvalidEventEnvelope::IdVersion`] when the id is not a UUID v7,
    /// [`InvalidEventEnvelope::Timestamp`] when the time lies before 1970 or out of range, and
    /// [`InvalidEventEnvelope::FieldReserved`] when `data` holds a common field.
    pub fn new(mut parts: EventEnvelopeParts) -> Result<Self, InvalidEventEnvelope> {
        if parts.id.as_uuid().get_version_num() != 7 {
            return Err(InvalidEventEnvelope::IdVersion);
        }
        let occurred_at_micros =
            micros::since_epoch(parts.occurred_at).ok_or(InvalidEventEnvelope::Timestamp)?;
        parts.occurred_at =
            micros::time_of(occurred_at_micros).ok_or(InvalidEventEnvelope::Timestamp)?;
        if Self::RESERVED_FIELDS
            .iter()
            .any(|name| parts.data.contains(name))
        {
            return Err(InvalidEventEnvelope::FieldReserved);
        }
        Ok(Self {
            parts,
            occurred_at_micros,
        })
    }

    /// The envelope of a pulled domain event.
    ///
    /// # Errors
    ///
    /// [`InvalidEventEnvelope::EventType`] when the event name is not an [`EventType`], and every
    /// error of [`IamDomainEvent::data`] and [`EventEnvelope::new`].
    pub fn of(event: &dyn IamDomainEvent) -> Result<Self, InvalidEventEnvelope> {
        Self::new(EventEnvelopeParts {
            id: event.event_id(),
            event_type: EventType::new(event.event_name())?,
            occurred_at: event.occurred_at(),
            aggregate_id: event.aggregate_id(),
            actor: event.actor().clone(),
            entity_version: event.entity_version(),
            data: event.data()?,
        })
    }

    /// The values of the envelope.
    #[must_use]
    pub const fn parts(&self) -> &EventEnvelopeParts {
        &self.parts
    }

    /// When the event happened, in whole microseconds since 1970.
    #[must_use]
    pub const fn occurred_at_micros(&self) -> i64 {
        self.occurred_at_micros
    }
}

#[cfg(test)]
mod tests;
