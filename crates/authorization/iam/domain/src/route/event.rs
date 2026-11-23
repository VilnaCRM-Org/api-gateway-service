//! The domain events of the `Route` aggregate, published on `iam.events.v1`.

use std::time::SystemTime;

use shared_domain::{DomainEvent, Uuid};

use crate::entity::aggregate_event::aggregate_event;
use crate::entity::event_envelope::IamDomainEvent;
use crate::error::InvalidEventEnvelope;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::event_data::{EventData, EventValue};
use crate::value_object::identifier::{ChangeId, RouteId};
use crate::value_object::path_pattern::PathPattern;
use crate::value_object::route_host::RouteHost;
use crate::value_object::service_name::ServiceName;

/// A route was created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCreated {
    /// The id of the event.
    pub event_id: Uuid,
    /// The created route.
    pub route_id: RouteId,
    /// The version of the route after the change: 1.
    pub version: EntityVersion,
    /// The host of the route.
    pub host: RouteHost,
    /// The path pattern of the route.
    pub path_pattern: PathPattern,
    /// The catalogue service of the route.
    pub service: ServiceName,
    /// Who created the route.
    pub actor: ActorRef,
    /// When the route was created.
    pub occurred_at: SystemTime,
}

aggregate_event!(RouteCreated, "iam.route.created", route_id);

impl RouteCreated {
    /// `routeId`, `host`, `pathPattern` and `service`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        route_identity(self.route_id, &self.host, &self.path_pattern)?
            .with("service", text(&self.service))
    }
}

/// A route was changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteUpdated {
    /// The id of the event.
    pub event_id: Uuid,
    /// The changed route.
    pub route_id: RouteId,
    /// The version of the route after the change.
    pub version: EntityVersion,
    /// The host of the route.
    pub host: RouteHost,
    /// The path pattern of the route after the change.
    pub path_pattern: PathPattern,
    /// The names of the changed properties.
    pub changed_fields: Vec<&'static str>,
    /// Whether the change is of the revocation class (it takes access away).
    pub revocation: bool,
    /// Who changed the route.
    pub actor: ActorRef,
    /// When the route changed.
    pub occurred_at: SystemTime,
}

aggregate_event!(RouteUpdated, "iam.route.updated", route_id);

impl RouteUpdated {
    /// `routeId`, `host`, `pathPattern`, `changedFields` and `revocation`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        let changed = self
            .changed_fields
            .iter()
            .map(|field| EventValue::Text((*field).to_owned()))
            .collect();
        route_identity(self.route_id, &self.host, &self.path_pattern)?
            .with("changedFields", EventValue::List(changed))?
            .with("revocation", EventValue::Bool(self.revocation))
    }
}

/// A route was deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDeleted {
    /// The id of the event.
    pub event_id: Uuid,
    /// The deleted route.
    pub route_id: RouteId,
    /// The version of the route after the change.
    pub version: EntityVersion,
    /// The host of the route.
    pub host: RouteHost,
    /// The path pattern of the route.
    pub path_pattern: PathPattern,
    /// Who deleted the route.
    pub actor: ActorRef,
    /// When the route was deleted.
    pub occurred_at: SystemTime,
}

aggregate_event!(RouteDeleted, "iam.route.deleted", route_id);

impl RouteDeleted {
    /// `routeId`, `host` and `pathPattern`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        route_identity(self.route_id, &self.host, &self.path_pattern)
    }
}

/// The route table of one host was applied: the gateway compiled and activated its routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteConfigurationApplied {
    /// The id of the event.
    pub event_id: Uuid,
    /// The change that the application belongs to; also the aggregate of the event.
    pub change_id: ChangeId,
    /// The host whose routes were applied.
    pub host: RouteHost,
    /// The number of routes of the host.
    pub route_count: u32,
    /// Who caused the application.
    pub actor: ActorRef,
    /// When the configuration was applied.
    pub occurred_at: SystemTime,
}

impl RouteConfigurationApplied {
    /// The type of the event on `iam.events.v1`.
    pub const NAME: &'static str = "iam.route.configuration_applied";

    /// `host` and `routeCount`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        EventData::new().with("host", text(&self.host))?.with(
            "routeCount",
            EventValue::Integer(i64::from(self.route_count)),
        )
    }
}

impl DomainEvent for RouteConfigurationApplied {
    fn event_id(&self) -> Uuid {
        self.event_id
    }

    fn aggregate_id(&self) -> Uuid {
        self.change_id.as_uuid()
    }

    fn occurred_at(&self) -> SystemTime {
        self.occurred_at
    }

    fn event_name(&self) -> &'static str {
        Self::NAME
    }
}

impl IamDomainEvent for RouteConfigurationApplied {
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

/// `routeId`, `host` and `pathPattern`, the start of every route event.
fn route_identity(
    id: RouteId,
    host: &RouteHost,
    path_pattern: &PathPattern,
) -> Result<EventData, InvalidEventEnvelope> {
    EventData::new()
        .with("routeId", text(&id))?
        .with("host", text(host))?
        .with("pathPattern", text(path_pattern))
}

/// The text form of a value.
fn text(value: &impl std::fmt::Display) -> EventValue {
    EventValue::Text(value.to_string())
}

#[cfg(test)]
mod tests;
