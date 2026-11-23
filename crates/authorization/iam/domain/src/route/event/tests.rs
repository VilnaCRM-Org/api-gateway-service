use std::time::{Duration, SystemTime};

use shared_domain::{DomainEvent as _, Uuid};

use super::{RouteConfigurationApplied, RouteCreated, RouteDeleted, RouteUpdated};
use crate::entity::event_envelope::{EventEnvelope, IamDomainEvent as _};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::event_data::EventValue;
use crate::value_object::identifier::{ChangeId, RouteId};
use crate::value_object::path_pattern::PathPattern;
use crate::value_object::route_host::RouteHost;
use crate::value_object::service_name::ServiceName;

const EVENT: &str = "01890a5d-ac96-774b-bcce-b302099a8057";
const ROUTE: &str = "7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b";
const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(1_700_000_000))
        .unwrap()
}

fn actor() -> ActorRef {
    ActorRef::User(Uuid::parse(USER).unwrap())
}

fn route_id() -> RouteId {
    RouteId::parse(ROUTE).unwrap()
}

fn host() -> RouteHost {
    RouteHost::new("api.example.com").unwrap()
}

fn pattern() -> PathPattern {
    PathPattern::new("/api/orders/{id}").unwrap()
}

fn version() -> EntityVersion {
    EntityVersion::new(2).unwrap()
}

fn text(value: &str) -> EventValue {
    EventValue::Text(value.to_owned())
}

fn field<'a>(envelope: &'a EventEnvelope, name: &str) -> &'a EventValue {
    envelope
        .parts()
        .data
        .fields()
        .iter()
        .find(|(field, _value)| field == name)
        .map(|(_field, value)| value)
        .unwrap()
}

#[test]
fn a_created_route_names_its_identity_and_service() {
    let event = RouteCreated {
        event_id: Uuid::parse(EVENT).unwrap(),
        route_id: route_id(),
        version: EntityVersion::INITIAL,
        host: host(),
        path_pattern: pattern(),
        service: ServiceName::new("core").unwrap(),
        actor: actor(),
        occurred_at: at(),
    };

    let envelope = EventEnvelope::of(&event).unwrap();

    assert_eq!(event.event_name(), "iam.route.created");
    assert_eq!(event.aggregate_id(), route_id().as_uuid());
    assert_eq!(event.entity_version(), Some(EntityVersion::INITIAL));
    assert_eq!(event.actor(), &actor());
    assert_eq!(field(&envelope, "routeId"), &text(ROUTE));
    assert_eq!(field(&envelope, "host"), &text("api.example.com"));
    assert_eq!(field(&envelope, "pathPattern"), &text("/api/orders/{id}"));
    assert_eq!(field(&envelope, "service"), &text("core"));
}

#[test]
fn an_updated_route_names_what_changed() {
    let event = RouteUpdated {
        event_id: Uuid::parse(EVENT).unwrap(),
        route_id: route_id(),
        version: version(),
        host: host(),
        path_pattern: pattern(),
        changed_fields: vec!["anonymous", "enforcement"],
        revocation: true,
        actor: actor(),
        occurred_at: at(),
    };

    let envelope = EventEnvelope::of(&event).unwrap();

    assert_eq!(event.event_name(), "iam.route.updated");
    assert_eq!(
        field(&envelope, "changedFields"),
        &EventValue::List(vec![text("anonymous"), text("enforcement")])
    );
    assert_eq!(field(&envelope, "revocation"), &EventValue::Bool(true));
}

#[test]
fn a_deleted_route_names_its_identity() {
    let event = RouteDeleted {
        event_id: Uuid::parse(EVENT).unwrap(),
        route_id: route_id(),
        version: version(),
        host: host(),
        path_pattern: pattern(),
        actor: actor(),
        occurred_at: at(),
    };

    let envelope = EventEnvelope::of(&event).unwrap();

    assert_eq!(event.event_name(), "iam.route.deleted");
    assert_eq!(field(&envelope, "routeId"), &text(ROUTE));
    assert_eq!(envelope.parts().data.fields().len(), 3);
}

#[test]
fn an_applied_configuration_names_the_host_and_the_route_count() {
    let change = ChangeId::parse(ROUTE).unwrap();
    let event = RouteConfigurationApplied {
        event_id: Uuid::parse(EVENT).unwrap(),
        change_id: change,
        host: host(),
        route_count: 12,
        actor: actor(),
        occurred_at: at(),
    };

    let envelope = EventEnvelope::of(&event).unwrap();

    assert_eq!(event.event_name(), "iam.route.configuration_applied");
    assert_eq!(event.aggregate_id(), change.as_uuid());
    assert_eq!(event.entity_version(), None);
    assert_eq!(field(&envelope, "host"), &text("api.example.com"));
    assert_eq!(field(&envelope, "routeCount"), &EventValue::Integer(12));
}
