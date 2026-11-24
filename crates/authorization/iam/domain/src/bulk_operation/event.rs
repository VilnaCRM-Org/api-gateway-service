//! The domain event of a bulk operation, published on `iam.events.v1`.

use std::time::SystemTime;

use shared_domain::{DomainEvent, Uuid};

use super::BulkKind;
use crate::entity::event_envelope::IamDomainEvent;
use crate::error::InvalidEventEnvelope;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::event_data::{EventData, EventValue};
use crate::value_object::identifier::BulkOperationId;
use crate::value_object::policy_version::PolicyVersion;

/// A bulk operation applied its last record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkOperationCompleted {
    /// The id of the event.
    pub event_id: Uuid,
    /// The completed operation; also the aggregate of the event.
    pub bulk_operation_id: BulkOperationId,
    /// What the operation changed.
    pub kind: BulkKind,
    /// How many records it applied.
    pub total_records: u64,
    /// The policy version of its first chunk.
    pub first_version: Option<PolicyVersion>,
    /// The policy version of its last chunk.
    pub last_version: Option<PolicyVersion>,
    /// Who asked for the change.
    pub actor: ActorRef,
    /// When the last chunk committed.
    pub occurred_at: SystemTime,
}

impl BulkOperationCompleted {
    /// The type of the event on `iam.events.v1`.
    pub const NAME: &'static str = "iam.bulk_operation.completed";

    /// `bulkOperationId`, `kind`, `totalRecords`, `firstVersion` and `lastVersion`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        let total = i64::try_from(self.total_records).unwrap_or(i64::MAX);
        let id = EventValue::Text(self.bulk_operation_id.to_string());
        EventData::new()
            .with("bulkOperationId", id)?
            .with("kind", EventValue::Text(self.kind.as_str().to_owned()))?
            .with("totalRecords", EventValue::Integer(total))?
            .with("firstVersion", version_value(self.first_version))?
            .with("lastVersion", version_value(self.last_version))
    }
}

/// The version as an integer field, or null when none committed.
fn version_value(version: Option<PolicyVersion>) -> EventValue {
    version.map_or(EventValue::Null, |version| {
        EventValue::Integer(version.value())
    })
}

impl DomainEvent for BulkOperationCompleted {
    fn event_id(&self) -> Uuid {
        self.event_id
    }

    fn aggregate_id(&self) -> Uuid {
        self.bulk_operation_id.as_uuid()
    }

    fn occurred_at(&self) -> SystemTime {
        self.occurred_at
    }

    fn event_name(&self) -> &'static str {
        Self::NAME
    }
}

impl IamDomainEvent for BulkOperationCompleted {
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
