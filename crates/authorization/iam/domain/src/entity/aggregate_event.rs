//! Shared plumbing of the aggregates of the gateway configuration: the event trait impls and the
//! way from recorded events to envelopes.

use std::any::Any;

use shared_domain::DomainEvent;

use crate::entity::event_envelope::{EventEnvelope, IamDomainEvent};
use crate::error::InvalidEventEnvelope;

/// The envelope of an event of one type, when the event has that type.
pub(crate) type Enveloper = fn(&dyn Any) -> Option<Result<EventEnvelope, InvalidEventEnvelope>>;

/// The envelope of `event` when it is an `E`.
pub(crate) fn envelope_as<E: IamDomainEvent>(
    event: &dyn Any,
) -> Option<Result<EventEnvelope, InvalidEventEnvelope>> {
    event
        .downcast_ref::<E>()
        .map(|event| EventEnvelope::of(event))
}

/// The envelopes of the drained `events`, in order, each made by the first of `envelopers` that
/// recognises the event.
///
/// # Errors
///
/// The [`InvalidEventEnvelope`] of the first event that cannot be enveloped, and
/// [`InvalidEventEnvelope::EventType`] for an event that none of the `envelopers` recognises.
pub(crate) fn envelopes_of(
    events: &[Box<dyn DomainEvent>],
    envelopers: &[Enveloper],
) -> Result<Vec<EventEnvelope>, InvalidEventEnvelope> {
    events
        .iter()
        .map(|event| {
            let event: &dyn Any = event.as_ref();
            envelopers
                .iter()
                .find_map(|enveloper| enveloper(event))
                .unwrap_or(Err(InvalidEventEnvelope::EventType))
        })
        .collect()
}

/// Implements [`DomainEvent`] and [`IamDomainEvent`] for an event with the fields `event_id`,
/// `$id_field`, `version`, `actor` and `occurred_at` and an inherent `event_data` method.
macro_rules! aggregate_event {
    ($event:ident, $name:literal, $id_field:ident) => {
        impl $event {
            /// The type of the event on `iam.events.v1`.
            pub const NAME: &'static str = $name;
        }

        impl ::shared_domain::DomainEvent for $event {
            fn event_id(&self) -> ::shared_domain::Uuid {
                self.event_id
            }

            fn aggregate_id(&self) -> ::shared_domain::Uuid {
                self.$id_field.as_uuid()
            }

            fn occurred_at(&self) -> ::std::time::SystemTime {
                self.occurred_at
            }

            fn event_name(&self) -> &'static str {
                Self::NAME
            }
        }

        impl $crate::entity::event_envelope::IamDomainEvent for $event {
            fn actor(&self) -> &$crate::value_object::actor_ref::ActorRef {
                &self.actor
            }

            fn entity_version(
                &self,
            ) -> Option<$crate::value_object::entity_version::EntityVersion> {
                Some(self.version)
            }

            fn data(
                &self,
            ) -> Result<
                $crate::value_object::event_data::EventData,
                $crate::error::InvalidEventEnvelope,
            > {
                self.event_data()
            }
        }
    };
}

pub(crate) use aggregate_event;
