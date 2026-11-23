//! The domain events of the `RatePolicy` aggregate, published on `iam.events.v1`.

use std::time::SystemTime;

use shared_domain::Uuid;

use crate::entity::aggregate_event::aggregate_event;
use crate::error::InvalidEventEnvelope;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::event_data::{EventData, EventValue};
use crate::value_object::identifier::RatePolicyId;

/// A rate policy was created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatePolicyCreated {
    /// The id of the event.
    pub event_id: Uuid,
    /// The created rate policy.
    pub rate_policy_id: RatePolicyId,
    /// The version of the rate policy after the change: 1.
    pub version: EntityVersion,
    /// The name of the rate policy.
    pub name: String,
    /// Who created the rate policy.
    pub actor: ActorRef,
    /// When the rate policy was created.
    pub occurred_at: SystemTime,
}

aggregate_event!(RatePolicyCreated, "iam.rate_policy.created", rate_policy_id);

impl RatePolicyCreated {
    /// `ratePolicyId` and `name`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        identity(self.rate_policy_id, &self.name)
    }
}

/// A rate policy changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatePolicyUpdated {
    /// The id of the event.
    pub event_id: Uuid,
    /// The changed rate policy.
    pub rate_policy_id: RatePolicyId,
    /// The version of the rate policy after the change.
    pub version: EntityVersion,
    /// The name of the rate policy after the change.
    pub name: String,
    /// The names of the changed properties.
    pub changed_fields: Vec<&'static str>,
    /// Who changed the rate policy.
    pub actor: ActorRef,
    /// When the rate policy changed.
    pub occurred_at: SystemTime,
}

aggregate_event!(RatePolicyUpdated, "iam.rate_policy.updated", rate_policy_id);

impl RatePolicyUpdated {
    /// `ratePolicyId`, `name` and `changedFields`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        let changed = self
            .changed_fields
            .iter()
            .map(|field| EventValue::Text((*field).to_owned()))
            .collect();
        identity(self.rate_policy_id, &self.name)?.with("changedFields", EventValue::List(changed))
    }
}

/// A rate policy was deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatePolicyDeleted {
    /// The id of the event.
    pub event_id: Uuid,
    /// The deleted rate policy.
    pub rate_policy_id: RatePolicyId,
    /// The version of the rate policy after the change.
    pub version: EntityVersion,
    /// The name of the rate policy.
    pub name: String,
    /// Who deleted the rate policy.
    pub actor: ActorRef,
    /// When the rate policy was deleted.
    pub occurred_at: SystemTime,
}

aggregate_event!(RatePolicyDeleted, "iam.rate_policy.deleted", rate_policy_id);

impl RatePolicyDeleted {
    /// `ratePolicyId` and `name`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        identity(self.rate_policy_id, &self.name)
    }
}

/// `ratePolicyId` and `name`, the start of every rate policy event.
fn identity(id: RatePolicyId, name: &str) -> Result<EventData, InvalidEventEnvelope> {
    EventData::new()
        .with("ratePolicyId", EventValue::Text(id.to_string()))?
        .with("name", EventValue::Text(name.to_owned()))
}
