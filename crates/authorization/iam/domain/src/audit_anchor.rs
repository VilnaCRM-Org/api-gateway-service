//! The event that publishes the head of the security audit chain, so that the audit history can
//! be verified from outside IAM (FR-43).

use std::time::SystemTime;

use shared_domain::{DomainEvent, Uuid};

use crate::entity::event_envelope::IamDomainEvent;
use crate::error::InvalidEventEnvelope;
use crate::value_object::actor_ref::{ActorRef, SystemComponent};
use crate::value_object::audit_chain_head::AuditChainHead;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::event_data::{EventData, EventValue};

/// Who anchors the chain, when, and under which event id: the values that the `Clock` and
/// `UuidGenerator` ports give the maintenance task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchorStamp {
    /// The id of the event, a UUID v7 from the `UuidGenerator` port.
    pub event_id: Uuid,
    /// When the chain is anchored, from the `Clock` port.
    pub occurred_at: SystemTime,
}

/// The head of the security audit chain was published: the sequence number and the hash of its
/// newest record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityAuditAnchored {
    event_id: Uuid,
    head: AuditChainHead,
    actor: ActorRef,
    occurred_at: SystemTime,
}

impl SecurityAuditAnchored {
    /// The type of the event on `iam.events.v1`.
    pub const NAME: &'static str = "iam.security_audit.anchored";

    /// The anchoring of `head` as `system:maintenance`.
    #[must_use]
    pub const fn new(stamp: AnchorStamp, head: AuditChainHead) -> Self {
        Self {
            event_id: stamp.event_id,
            head,
            actor: ActorRef::System(SystemComponent::Maintenance),
            occurred_at: stamp.occurred_at,
        }
    }

    /// The anchored head.
    #[must_use]
    pub const fn head(&self) -> &AuditChainHead {
        &self.head
    }

    /// `seq` and `hash`, the lower-case hexadecimal hash of the newest audit record.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        EventData::new()
            .with("seq", EventValue::Integer(self.head.seq()))?
            .with("hash", EventValue::Text(self.head.hash().to_string()))
    }
}

impl DomainEvent for SecurityAuditAnchored {
    fn event_id(&self) -> Uuid {
        self.event_id
    }

    /// An anchoring is its own aggregate: it is keyed by its event id.
    fn aggregate_id(&self) -> Uuid {
        self.event_id
    }

    fn occurred_at(&self) -> SystemTime {
        self.occurred_at
    }

    fn event_name(&self) -> &'static str {
        Self::NAME
    }
}

impl IamDomainEvent for SecurityAuditAnchored {
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
