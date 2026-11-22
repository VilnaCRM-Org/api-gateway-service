use std::time::{Duration, SystemTime};

use shared_domain::Uuid;

use super::{OpenApiSpecLoaded, OpenApiSpecRetired};
use crate::entity::event_envelope::{EventEnvelope, IamDomainEvent};
use crate::value_object::actor_ref::{ActorRef, SystemComponent};
use crate::value_object::content_hash::ContentHash;
use crate::value_object::event_data::{EventData, EventValue};
use crate::value_object::identifier::SpecId;
use crate::value_object::service_name::ServiceName;

const EVENT: &str = "01890a5d-ac96-774b-bcce-b302099a8057";
const SPEC: &str = "5b2e8c1d-3f4a-4b6c-8d9e-0a1b2c3d4e5f";

fn event_id() -> Uuid {
    Uuid::parse(EVENT).unwrap()
}

fn spec_id() -> SpecId {
    SpecId::parse(SPEC).unwrap()
}

fn actor() -> ActorRef {
    ActorRef::System(SystemComponent::Startup)
}

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(1_700_000_000))
        .unwrap()
}

fn service() -> ServiceName {
    ServiceName::new("billing").unwrap()
}

fn text(value: &str) -> EventValue {
    EventValue::Text(value.to_owned())
}

fn data(fields: Vec<(&str, EventValue)>) -> EventData {
    fields
        .into_iter()
        .try_fold(EventData::new(), |data, (name, value)| {
            data.with(name, value)
        })
        .unwrap()
}

/// Checks the common accessors of a specification event and that it has an envelope.
fn assert_common(event: &dyn IamDomainEvent, name: &str) {
    assert_eq!(event.event_name(), name);
    assert_eq!(event.event_id(), event_id());
    assert_eq!(event.aggregate_id(), spec_id().as_uuid());
    assert_eq!(event.occurred_at(), at());
    assert_eq!(event.actor(), &actor());
    assert_eq!(event.entity_version(), None);
    let envelope = EventEnvelope::of(event).unwrap();
    assert_eq!(envelope.parts().event_type.as_str(), name);
}

#[test]
fn a_loaded_version_names_its_service_hash_and_operation_count() {
    let event = OpenApiSpecLoaded {
        event_id: event_id(),
        spec_id: spec_id(),
        service: service(),
        content_hash: ContentHash::new(&[0xab; 32]).unwrap(),
        operation_count: 42,
        actor: actor(),
        occurred_at: at(),
    };

    assert_eq!(OpenApiSpecLoaded::NAME, "iam.openapi_spec.loaded");
    assert_common(&event, OpenApiSpecLoaded::NAME);
    assert_eq!(
        event.data().unwrap(),
        data(vec![
            ("specId", text(SPEC)),
            ("service", text("billing")),
            ("contentHash", text(&"ab".repeat(32))),
            ("operationCount", EventValue::Integer(42)),
        ])
    );
}

#[test]
fn a_retired_version_names_its_service() {
    let event = OpenApiSpecRetired {
        event_id: event_id(),
        spec_id: spec_id(),
        service: service(),
        actor: actor(),
        occurred_at: at(),
    };

    assert_eq!(OpenApiSpecRetired::NAME, "iam.openapi_spec.retired");
    assert_common(&event, OpenApiSpecRetired::NAME);
    assert_eq!(
        event.data().unwrap(),
        data(vec![("specId", text(SPEC)), ("service", text("billing"))])
    );
}
