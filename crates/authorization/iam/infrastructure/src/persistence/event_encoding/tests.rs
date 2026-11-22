use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, EntityVersion, EventData, EventEnvelope, EventEnvelopeParts, EventType, EventValue,
    InvalidEventEnvelope, PolicyVersion,
};
use serde_json::{Value, json};
use shared_domain::Uuid;
use test_support::seed::TestRng;
use test_support::unit_of_work::{event_envelope, uuid_v7};

const ID: &str = "0190f2a8-7b3c-7d4e-8f00-000000000001";
const ROLE: &str = "0190f2a8-7b3c-7d4e-8f00-0000000000aa";
const USER: &str = "0190f2a8-7b3c-7d4e-8f00-123456789abc";
const TOKEN: &str = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl";

fn envelope(micros: u64, entity_version: Option<EntityVersion>, data: EventData) -> EventEnvelope {
    EventEnvelope::new(EventEnvelopeParts {
        id: Uuid::parse(ID).unwrap(),
        event_type: EventType::new("iam.role.created").unwrap(),
        occurred_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_micros(micros))
            .unwrap(),
        aggregate_id: Uuid::parse(ROLE).unwrap(),
        actor: ActorRef::User(Uuid::parse(USER).unwrap()),
        entity_version,
        data,
    })
    .unwrap()
}

fn decoded(encoded: &str) -> Value {
    serde_json::from_str(encoded).unwrap()
}

#[test]
fn an_envelope_encodes_as_id_type_occurred_at_and_data_with_the_common_fields() {
    let nested = EventData::new()
        .with("kind", EventValue::Text("user".to_owned()))
        .unwrap();
    let data = EventData::new()
        .with("name", EventValue::Text("readers".to_owned()))
        .unwrap()
        .with("grantCount", EventValue::Integer(-2))
        .unwrap()
        .with("system", EventValue::Bool(true))
        .unwrap()
        .with("expiresAt", EventValue::Null)
        .unwrap()
        .with(
            "addedKeys",
            EventValue::List(vec![EventValue::Text("rest:core:GET /a".to_owned())]),
        )
        .unwrap()
        .with("subject", EventValue::Object(nested))
        .unwrap();
    let event = envelope(1_700_000_000_123_456, Some(EntityVersion::INITIAL), data);

    let encoded = super::encode(&event, PolicyVersion::new(42).unwrap()).unwrap();

    assert_eq!(
        decoded(&encoded),
        json!({
            "id": ID,
            "type": "iam.role.created",
            "occurredAt": "2023-11-14T22:13:20.123456Z",
            "data": {
                "aggregateId": ROLE,
                "entityVersion": 1,
                "actor": format!("user:{USER}"),
                "policyVersion": 42,
                "name": "readers",
                "grantCount": -2,
                "system": true,
                "expiresAt": null,
                "addedKeys": ["rest:core:GET /a"],
                "subject": {"kind": "user"}
            }
        })
    );
    assert!(!encoded.contains('\n'));
}

#[test]
fn an_unversioned_aggregate_has_a_null_entity_version() {
    let event = envelope(0, None, EventData::new());

    let encoded = super::encode(&event, PolicyVersion::new(0).unwrap()).unwrap();

    let value = decoded(&encoded);
    assert_eq!(value["data"]["entityVersion"], Value::Null);
    assert_eq!(value["data"]["policyVersion"], json!(0));
    assert_eq!(value["occurredAt"], json!("1970-01-01T00:00:00.000000Z"));
}

#[test]
fn every_seeded_envelope_has_a_v7_id_a_catalogue_type_and_a_utc_time() {
    let mut rng = TestRng::from_env();
    for _round in 0..32 {
        let aggregate = uuid_v7(&mut rng);
        let event = event_envelope(&mut rng, aggregate);

        let value = decoded(&super::encode(&event, PolicyVersion::new(7).unwrap()).unwrap());

        let id = Uuid::parse(value["id"].as_str().unwrap()).unwrap();
        let occurred_at = value["occurredAt"].as_str().unwrap();
        assert_eq!(id.as_uuid().get_version_num(), 7);
        assert_eq!(value["type"], json!("iam.role.updated"));
        assert!(occurred_at.ends_with('Z'), "{occurred_at}");
        assert_eq!(occurred_at.get(10..11), Some("T"));
        assert_eq!(value["data"]["aggregateId"], json!(aggregate.to_string()));
        assert!(!value.to_string().contains("eyJ"));
    }
}

#[test]
fn an_envelope_at_the_bound_is_accepted_and_one_byte_more_is_too_large() {
    let empty = envelope(0, None, EventData::new());
    let version = PolicyVersion::new(1).unwrap();
    let base = super::encode(
        &envelope(
            0,
            None,
            EventData::new()
                .with("padding", EventValue::Text(String::new()))
                .unwrap(),
        ),
        version,
    )
    .unwrap()
    .len();
    let fill = EventEnvelope::MAX_ENCODED_BYTES - base;
    let padded = |length: usize| {
        envelope(
            0,
            None,
            EventData::new()
                .with("padding", EventValue::Text("a".repeat(length)))
                .unwrap(),
        )
    };

    let largest = super::encode(&padded(fill), version).unwrap();
    let larger = super::encode(&padded(fill + 1), version);

    assert_eq!(largest.len(), 65_536);
    assert_eq!(larger, Err(InvalidEventEnvelope::TooLarge));
    assert!(super::encode(&empty, version).unwrap().len() < base);
}

#[test]
fn no_token_and_no_specification_body_reaches_the_payload() {
    let token = EventData::new().with("note", EventValue::Text(TOKEN.to_owned()));
    let specification = EventData::new().with(
        "note",
        EventValue::Text("openapi: 3.1.0\ninfo:\n  title: core".to_owned()),
    );
    let named = EventData::new().with("accessToken", EventValue::Text("x".to_owned()));

    assert_eq!(token, Err(InvalidEventEnvelope::Credential));
    assert_eq!(specification, Err(InvalidEventEnvelope::ControlCharacter));
    assert_eq!(named, Err(InvalidEventEnvelope::FieldForbidden));
}

#[test]
fn a_time_after_the_year_9999_is_not_an_rfc_3339_time() {
    assert_eq!(
        super::rfc3339(253_402_300_799_999_999).unwrap(),
        "9999-12-31T23:59:59.999999Z"
    );
    assert_eq!(
        super::rfc3339(253_402_300_800_000_000),
        Err(InvalidEventEnvelope::Timestamp)
    );
    assert_eq!(
        super::rfc3339(i64::MAX),
        Err(InvalidEventEnvelope::Timestamp)
    );
    let event = envelope(253_402_300_800_000_000, None, EventData::new());
    assert_eq!(
        super::encode(&event, PolicyVersion::new(1).unwrap()),
        Err(InvalidEventEnvelope::Timestamp)
    );
}
