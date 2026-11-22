use std::time::{Duration, SystemTime};

use rstest::rstest;
use shared_domain::{DomainEvent, Uuid};

use super::{EventEnvelope, EventEnvelopeParts, IamDomainEvent};
use crate::error::InvalidEventEnvelope;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::event_data::{EventData, EventValue};
use crate::value_object::event_type::EventType;

const ID: &str = "0190f2a8-7b3c-7d4e-8f00-000000000001";
const V4: &str = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b";
const ROLE: &str = "0190f2a8-7b3c-7d4e-8f00-0000000000aa";
const USER: &str = "0190f2a8-7b3c-7d4e-8f00-123456789abc";

fn at_nanos(nanos: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_nanos(nanos))
        .unwrap()
}

fn parts() -> EventEnvelopeParts {
    EventEnvelopeParts {
        id: Uuid::parse(ID).unwrap(),
        event_type: EventType::new("iam.role.created").unwrap(),
        occurred_at: at_nanos(1_700_000_000_123_456_789),
        aggregate_id: Uuid::parse(ROLE).unwrap(),
        actor: ActorRef::User(Uuid::parse(USER).unwrap()),
        entity_version: Some(EntityVersion::INITIAL),
        data: EventData::new()
            .with("name", EventValue::Text("readers".to_owned()))
            .unwrap(),
    }
}

#[test]
fn an_envelope_keeps_its_values_and_its_time_in_microseconds() {
    let envelope = EventEnvelope::new(parts()).unwrap();

    assert_eq!(envelope.occurred_at_micros(), 1_700_000_000_123_456);
    assert_eq!(
        envelope.parts().occurred_at,
        at_nanos(1_700_000_000_123_456_000)
    );
    assert_eq!(
        EventEnvelope::new(envelope.parts().clone()).unwrap(),
        envelope
    );
    assert_eq!(envelope.parts().event_type.as_str(), "iam.role.created");
    assert_eq!(envelope.parts().data, parts().data);
    assert_eq!(EventEnvelope::MAX_ENCODED_BYTES, 65_536);
}

#[test]
fn rejects_an_id_that_is_not_a_uuid_v7() {
    let envelope = EventEnvelope::new(EventEnvelopeParts {
        id: Uuid::parse(V4).unwrap(),
        ..parts()
    });

    assert_eq!(envelope, Err(InvalidEventEnvelope::IdVersion));
}

#[rstest]
#[case::before_1970(SystemTime::UNIX_EPOCH.checked_sub(Duration::from_secs(1)).unwrap())]
#[case::past_the_range(SystemTime::UNIX_EPOCH.checked_add(Duration::from_micros(u64::MAX)).unwrap())]
fn rejects_a_time_out_of_range(#[case] occurred_at: SystemTime) {
    let envelope = EventEnvelope::new(EventEnvelopeParts {
        occurred_at,
        ..parts()
    });

    assert_eq!(envelope, Err(InvalidEventEnvelope::Timestamp));
}

#[rstest]
#[case("aggregateId")]
#[case("entityVersion")]
#[case("actor")]
#[case("policyVersion")]
fn rejects_a_common_field_among_the_events_own(#[case] name: &str) {
    let data = EventData::new().with(name, EventValue::Null).unwrap();

    let envelope = EventEnvelope::new(EventEnvelopeParts { data, ..parts() });

    assert_eq!(envelope, Err(InvalidEventEnvelope::FieldReserved));
}

/// A domain event of each value kind, with a configurable name and data.
#[derive(Debug)]
struct Recorded {
    name: &'static str,
    data: Result<EventData, InvalidEventEnvelope>,
    actor: ActorRef,
}

impl DomainEvent for Recorded {
    fn event_id(&self) -> Uuid {
        Uuid::parse(ID).unwrap()
    }

    fn aggregate_id(&self) -> Uuid {
        Uuid::parse(ROLE).unwrap()
    }

    fn occurred_at(&self) -> SystemTime {
        at_nanos(1_700_000_000_000_000_000)
    }

    fn event_name(&self) -> &'static str {
        self.name
    }
}

impl IamDomainEvent for Recorded {
    fn actor(&self) -> &ActorRef {
        &self.actor
    }

    fn entity_version(&self) -> Option<EntityVersion> {
        EntityVersion::new(3).ok()
    }

    fn data(&self) -> Result<EventData, InvalidEventEnvelope> {
        self.data.clone()
    }
}

fn recorded(name: &'static str, data: Result<EventData, InvalidEventEnvelope>) -> Recorded {
    Recorded {
        name,
        data,
        actor: ActorRef::User(Uuid::parse(USER).unwrap()),
    }
}

#[test]
fn a_pulled_domain_event_becomes_an_envelope() {
    let data = EventData::new()
        .with("revoked", EventValue::Bool(false))
        .unwrap();
    let event = recorded("iam.user_role.assigned", Ok(data.clone()));

    let envelope = EventEnvelope::of(&event).unwrap();

    let parts = envelope.parts();
    assert_eq!(parts.id, Uuid::parse(ID).unwrap());
    assert_eq!(parts.event_type.as_str(), "iam.user_role.assigned");
    assert_eq!(parts.aggregate_id, Uuid::parse(ROLE).unwrap());
    assert_eq!(parts.actor, event.actor);
    assert_eq!(parts.entity_version, EntityVersion::new(3).ok());
    assert_eq!(parts.data, data);
    assert_eq!(envelope.occurred_at_micros(), 1_700_000_000_000_000);
}

#[rstest]
#[case::bad_name(
    recorded("role.created", Ok(EventData::new())),
    InvalidEventEnvelope::EventType
)]
#[case::bad_data(
    recorded("iam.role.created", Err(InvalidEventEnvelope::Credential)),
    InvalidEventEnvelope::Credential
)]
fn an_event_with_a_bad_name_or_bad_data_has_no_envelope(
    #[case] event: Recorded,
    #[case] error: InvalidEventEnvelope,
) {
    assert_eq!(EventEnvelope::of(&event), Err(error));
}
