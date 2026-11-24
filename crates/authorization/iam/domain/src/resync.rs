//! The resync of the policy state (FR-78): the statements that start a new log epoch and publish
//! the unchanged state of the entities again, and the event that records it.

use std::time::SystemTime;

use shared_domain::{DomainEvent, Uuid};

use crate::bulk_operation::BulkOperationParts;
use crate::entity::event_envelope::IamDomainEvent;
use crate::error::{InvalidEventEnvelope, InvalidIamValue};
use crate::state::key::StateKey;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::audit_summary::AuditSummary;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::event_data::{EventData, EventValue};
use crate::value_object::identifier::BulkOperationId;
use crate::value_object::log_epoch::LogEpoch;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::service_name::ServiceName;

/// The write that starts a new log epoch.
///
/// The stored log epoch moves from `from` to `to`, and the policy version rises to `version_floor`
/// when it is below it, so that the version of the transaction, the next one, lies above every
/// version the state topic holds.
///
/// The write runs inside the transaction of the change, after the policy epoch row is locked and
/// before the next policy version is taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochChange {
    from: LogEpoch,
    to: LogEpoch,
    version_floor: PolicyVersion,
}

impl EpochChange {
    /// The change from the log epoch `from` to the one that follows it.
    ///
    /// # Errors
    ///
    /// [`InvalidIamValue::LogEpochNegative`] when the counter of the log epoch cannot grow.
    pub fn new(from: LogEpoch, version_floor: PolicyVersion) -> Result<Self, InvalidIamValue> {
        let to = from.next().ok_or(InvalidIamValue::LogEpochNegative)?;
        Ok(Self {
            from,
            to,
            version_floor,
        })
    }

    /// The log epoch the stored row must hold; any other stored epoch refuses the change as a
    /// conflict.
    #[must_use]
    pub const fn from(&self) -> LogEpoch {
        self.from
    }

    /// The log epoch the row holds after the change.
    #[must_use]
    pub const fn to(&self) -> LogEpoch {
        self.to
    }

    /// The version the policy version rises to when it is lower.
    #[must_use]
    pub const fn version_floor(&self) -> PolicyVersion {
        self.version_floor
    }
}

/// The start of a resync: the new log epoch and the pending bulk operation under it.
///
/// Both are written in one transaction, so an operation never exists without its epoch and the
/// epoch never starts without its operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResyncStart {
    epoch: EpochChange,
    operation: BulkOperationParts,
}

impl ResyncStart {
    /// The start of a resync through `epoch` that `operation` completes.
    #[must_use]
    pub const fn new(epoch: EpochChange, operation: BulkOperationParts) -> Self {
        Self { epoch, operation }
    }

    /// The change of the log epoch.
    #[must_use]
    pub const fn epoch(&self) -> &EpochChange {
        &self.epoch
    }

    /// The pending bulk operation to store.
    #[must_use]
    pub const fn operation(&self) -> &BulkOperationParts {
        &self.operation
    }
}

/// The entities whose unchanged state a transaction publishes again: the records of `keys` and
/// the catalogue records (the manifest and every chunk) of `services`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Republication {
    keys: Vec<StateKey>,
    services: Vec<ServiceName>,
}

impl Republication {
    /// The republication of `keys` and of the catalogues of `services`.
    #[must_use]
    pub const fn new(keys: Vec<StateKey>, services: Vec<ServiceName>) -> Self {
        Self { keys, services }
    }

    /// The keys of the entities.
    #[must_use]
    pub fn keys(&self) -> &[StateKey] {
        &self.keys
    }

    /// The services whose catalogue records are published again.
    #[must_use]
    pub fn services(&self) -> &[ServiceName] {
        &self.services
    }
}

/// One entity of the policy that a resync publishes: a record of its own, or the catalogue of a
/// service.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum InventoryEntry {
    /// A role, a subject, an upstream, a route or a rate policy.
    State(StateKey),
    /// The manifest and the chunks of the catalogue of a service.
    Catalogue(ServiceName),
}

impl InventoryEntry {
    /// Splits `entries` into the keys and the services of a [`Republication`].
    #[must_use]
    pub fn republication(entries: Vec<Self>) -> Republication {
        let mut keys = Vec::new();
        let mut services = Vec::new();
        for entry in entries {
            match entry {
                Self::State(key) => keys.push(key),
                Self::Catalogue(service) => services.push(service),
            }
        }
        Republication::new(keys, services)
    }
}

/// A policy resync started: the policy moved to a new log epoch and its complete state is
/// republished by the bulk operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyResynced {
    /// The id of the event.
    pub event_id: Uuid,
    /// The bulk operation that republishes the state; also the aggregate of the event.
    pub bulk_operation_id: BulkOperationId,
    /// The log epoch the republished records carry.
    pub log_epoch: LogEpoch,
    /// The policy version before the resync.
    pub from_version: PolicyVersion,
    /// The policy version the new log epoch starts at, above every version of the topic.
    pub to_version: PolicyVersion,
    /// Why the operator resynced.
    pub reason: AuditSummary,
    /// Who asked for the resync.
    pub actor: ActorRef,
    /// When the resync started.
    pub occurred_at: SystemTime,
}

impl PolicyResynced {
    /// The type of the event on `iam.events.v1`.
    pub const NAME: &'static str = "iam.policy.resynced";

    /// `logEpoch`, `fromVersion`, `toVersion`, `reason` and `bulkOperationId`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        let from_version = EventValue::Integer(self.from_version.value());
        EventData::new()
            .with("logEpoch", EventValue::Integer(self.log_epoch.value()))?
            .with("fromVersion", from_version)?
            .with("toVersion", EventValue::Integer(self.to_version.value()))?
            .with("reason", EventValue::Text(self.reason.as_str().to_owned()))?
            .with(
                "bulkOperationId",
                EventValue::Text(self.bulk_operation_id.to_string()),
            )
    }
}

impl DomainEvent for PolicyResynced {
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

impl IamDomainEvent for PolicyResynced {
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

#[cfg(test)]
mod tests;
