use std::time::{Duration, SystemTime};

use shared_domain::{DomainEvent as _, Uuid};

use super::{AnchorStamp, SecurityAuditAnchored};
use crate::entity::event_envelope::{EventEnvelope, IamDomainEvent as _};
use crate::value_object::actor_ref::{ActorRef, SystemComponent};
use crate::value_object::audit_chain_head::AuditChainHead;
use crate::value_object::audit_hash::AuditHash;
use crate::value_object::event_data::EventValue;

const EVENT: &str = "01890a5d-ac96-774b-bcce-b302099a8057";

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(1_700_000_000))
        .unwrap()
}

fn head() -> AuditChainHead {
    AuditChainHead::new(42, AuditHash::new(&[0xab; AuditHash::LENGTH]).unwrap()).unwrap()
}

fn anchored() -> SecurityAuditAnchored {
    SecurityAuditAnchored::new(
        AnchorStamp {
            event_id: Uuid::parse(EVENT).unwrap(),
            occurred_at: at(),
        },
        head(),
    )
}

#[test]
fn the_event_is_named_after_the_anchoring_and_keyed_by_its_own_id() {
    let event = anchored();

    assert_eq!(event.event_name(), "iam.security_audit.anchored");
    assert_eq!(event.event_id(), Uuid::parse(EVENT).unwrap());
    assert_eq!(event.aggregate_id(), event.event_id());
    assert_eq!(event.occurred_at(), at());
    assert_eq!(event.entity_version(), None);
    assert_eq!(event.head(), &head());
}

#[test]
fn the_event_is_caused_by_the_maintenance_task() {
    assert_eq!(
        anchored().actor(),
        &ActorRef::System(SystemComponent::Maintenance)
    );
}

#[test]
fn the_data_carries_the_sequence_number_and_the_hex_hash_of_the_head() {
    let data = anchored().data().unwrap();

    assert_eq!(
        data.fields(),
        [
            ("seq".to_owned(), EventValue::Integer(42)),
            ("hash".to_owned(), EventValue::Text("ab".repeat(32))),
        ]
    );
}

#[test]
fn the_event_can_be_enveloped_with_its_type_and_actor() {
    let envelope = EventEnvelope::of(&anchored()).unwrap();

    assert_eq!(
        envelope.parts().event_type.as_str(),
        "iam.security_audit.anchored"
    );
    assert_eq!(
        envelope.parts().actor,
        ActorRef::System(SystemComponent::Maintenance)
    );
    assert_eq!(envelope.parts().aggregate_id, Uuid::parse(EVENT).unwrap());
}
