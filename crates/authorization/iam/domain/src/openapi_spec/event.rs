//! The domain events of the `OpenApiSpec` aggregate, published on `iam.events.v1`. They carry
//! identifiers, the service and the hash, never the document.

use std::time::SystemTime;

use shared_domain::{DomainEvent, Uuid};

use crate::entity::event_envelope::IamDomainEvent;
use crate::error::InvalidEventEnvelope;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::content_hash::ContentHash;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::event_data::{EventData, EventValue};
use crate::value_object::identifier::SpecId;
use crate::value_object::service_name::ServiceName;

/// Implements [`DomainEvent`] and [`IamDomainEvent`] for a specification event with the fields
/// `event_id`, `spec_id`, `actor` and `occurred_at` and an inherent `event_data` method. A version
/// is immutable, so the events name no entity version.
macro_rules! spec_event {
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

/// An `OpenAPI` specification version was loaded as a draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenApiSpecLoaded {
    /// The id of the event.
    pub event_id: Uuid,
    /// The loaded version.
    pub spec_id: SpecId,
    /// The service of the document.
    pub service: ServiceName,
    /// The SHA-256 hash of the document.
    pub content_hash: ContentHash,
    /// The number of operations of the document.
    pub operation_count: u32,
    /// Who loaded the version.
    pub actor: ActorRef,
    /// When the version was loaded.
    pub occurred_at: SystemTime,
}

spec_event!(OpenApiSpecLoaded, "iam.openapi_spec.loaded");

impl OpenApiSpecLoaded {
    /// `specId`, `service`, `contentHash` and `operationCount`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        EventData::new()
            .with("specId", text(&self.spec_id))?
            .with("service", text(&self.service))?
            .with("contentHash", text(&self.content_hash))?
            .with(
                "operationCount",
                EventValue::Integer(i64::from(self.operation_count)),
            )
    }
}

/// An active `OpenAPI` specification version was retired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenApiSpecRetired {
    /// The id of the event.
    pub event_id: Uuid,
    /// The retired version.
    pub spec_id: SpecId,
    /// The service of the document.
    pub service: ServiceName,
    /// Who retired the version.
    pub actor: ActorRef,
    /// When the version was retired.
    pub occurred_at: SystemTime,
}

spec_event!(OpenApiSpecRetired, "iam.openapi_spec.retired");

impl OpenApiSpecRetired {
    /// `specId` and `service`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        EventData::new()
            .with("specId", text(&self.spec_id))?
            .with("service", text(&self.service))
    }
}

/// The text form of a value.
fn text(value: &impl std::fmt::Display) -> EventValue {
    EventValue::Text(value.to_string())
}

#[cfg(test)]
mod tests;
