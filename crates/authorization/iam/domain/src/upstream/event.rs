//! The domain events of the `Upstream` aggregate, published on `iam.events.v1`.

use std::time::SystemTime;

use shared_domain::Uuid;

use crate::entity::aggregate_event::aggregate_event;
use crate::error::InvalidEventEnvelope;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::event_data::{EventData, EventValue};
use crate::value_object::identifier::UpstreamId;
use crate::value_object::service_name::ServiceName;
use crate::value_object::upstream_name::UpstreamName;

/// An upstream was created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamCreated {
    /// The id of the event.
    pub event_id: Uuid,
    /// The created upstream.
    pub upstream_id: UpstreamId,
    /// The version of the upstream after the change: 1.
    pub version: EntityVersion,
    /// The name of the upstream.
    pub name: UpstreamName,
    /// The catalogue service the upstream serves.
    pub catalog_service: ServiceName,
    /// Who created the upstream.
    pub actor: ActorRef,
    /// When the upstream was created.
    pub occurred_at: SystemTime,
}

aggregate_event!(UpstreamCreated, "iam.upstream.created", upstream_id);

impl UpstreamCreated {
    /// `upstreamId`, `name` and `catalogService`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        identity(self.upstream_id, &self.name)?.with("catalogService", text(&self.catalog_service))
    }
}

/// The settings of an upstream changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamUpdated {
    /// The id of the event.
    pub event_id: Uuid,
    /// The changed upstream.
    pub upstream_id: UpstreamId,
    /// The version of the upstream after the change.
    pub version: EntityVersion,
    /// The name of the upstream.
    pub name: UpstreamName,
    /// The names of the changed settings.
    pub changed_fields: Vec<&'static str>,
    /// Who changed the upstream.
    pub actor: ActorRef,
    /// When the upstream changed.
    pub occurred_at: SystemTime,
}

aggregate_event!(UpstreamUpdated, "iam.upstream.updated", upstream_id);

impl UpstreamUpdated {
    /// `upstreamId`, `name` and `changedFields`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        let changed = self
            .changed_fields
            .iter()
            .map(|field| EventValue::Text((*field).to_owned()))
            .collect();
        identity(self.upstream_id, &self.name)?.with("changedFields", EventValue::List(changed))
    }
}

/// An upstream was deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamDeleted {
    /// The id of the event.
    pub event_id: Uuid,
    /// The deleted upstream.
    pub upstream_id: UpstreamId,
    /// The version of the upstream after the change.
    pub version: EntityVersion,
    /// The name of the upstream.
    pub name: UpstreamName,
    /// Who deleted the upstream.
    pub actor: ActorRef,
    /// When the upstream was deleted.
    pub occurred_at: SystemTime,
}

aggregate_event!(UpstreamDeleted, "iam.upstream.deleted", upstream_id);

impl UpstreamDeleted {
    /// `upstreamId` and `name`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        identity(self.upstream_id, &self.name)
    }
}

/// `upstreamId` and `name`, the start of every upstream event.
fn identity(id: UpstreamId, name: &UpstreamName) -> Result<EventData, InvalidEventEnvelope> {
    EventData::new()
        .with("upstreamId", text(&id))?
        .with("name", text(name))
}

/// The text form of a value.
fn text(value: &impl std::fmt::Display) -> EventValue {
    EventValue::Text(value.to_string())
}
