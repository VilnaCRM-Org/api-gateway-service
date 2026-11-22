//! JSON encoding of the envelopes of `iam.events.v1` through private DTOs.

use iam_domain::{EventData, EventEnvelope, EventValue, InvalidEventEnvelope, PolicyVersion};
use serde_json::{Map, Value};
use sqlx::types::time::OffsetDateTime;

/// The number of nanoseconds in one microsecond.
const NANOS_PER_MICRO: i128 = 1_000;

/// The wire form of one envelope; it never leaves this module.
struct EnvelopeDto {
    id: String,
    event_type: String,
    occurred_at: String,
    data: Map<String, Value>,
}

impl EnvelopeDto {
    /// Maps the envelope: `data` holds the common fields, the policy version of the committing
    /// transaction among them, then the event's own fields.
    fn of(
        envelope: &EventEnvelope,
        policy_version: PolicyVersion,
    ) -> Result<Self, InvalidEventEnvelope> {
        let parts = envelope.parts();
        let mut data = Map::new();
        data.insert(
            "aggregateId".to_owned(),
            Value::String(parts.aggregate_id.to_string()),
        );
        data.insert(
            "entityVersion".to_owned(),
            parts
                .entity_version
                .map_or(Value::Null, |version| Value::from(version.value())),
        );
        data.insert("actor".to_owned(), Value::String(parts.actor.to_string()));
        data.insert(
            "policyVersion".to_owned(),
            Value::from(policy_version.value()),
        );
        data.extend(object(&parts.data));
        Ok(Self {
            id: parts.id.to_string(),
            event_type: parts.event_type.as_str().to_owned(),
            occurred_at: rfc3339(envelope.occurred_at_micros())?,
            data,
        })
    }

    /// The JSON object `{id, type, occurredAt, data}`.
    fn into_json(self) -> Value {
        let mut envelope = Map::new();
        envelope.insert("id".to_owned(), Value::String(self.id));
        envelope.insert("type".to_owned(), Value::String(self.event_type));
        envelope.insert("occurredAt".to_owned(), Value::String(self.occurred_at));
        envelope.insert("data".to_owned(), Value::Object(self.data));
        Value::Object(envelope)
    }
}

/// Encodes the envelope as compact JSON with the policy version of the committing transaction.
///
/// # Errors
///
/// [`InvalidEventEnvelope::Timestamp`] when the time cannot be written as an RFC 3339 UTC time,
/// and [`InvalidEventEnvelope::TooLarge`] when the encoding exceeds
/// [`EventEnvelope::MAX_ENCODED_BYTES`].
pub fn encode(
    envelope: &EventEnvelope,
    policy_version: PolicyVersion,
) -> Result<String, InvalidEventEnvelope> {
    let encoded = EnvelopeDto::of(envelope, policy_version)?
        .into_json()
        .to_string();
    if encoded.len() > EventEnvelope::MAX_ENCODED_BYTES {
        return Err(InvalidEventEnvelope::TooLarge);
    }
    Ok(encoded)
}

/// The RFC 3339 UTC form of a time in microseconds since 1970, always with six fractional digits,
/// such as `2023-11-14T22:13:20.123456Z`.
///
/// # Errors
///
/// [`InvalidEventEnvelope::Timestamp`] when the time lies before 1970 or after the year 9999.
pub fn rfc3339(micros: i64) -> Result<String, InvalidEventEnvelope> {
    u64::try_from(micros)
        .ok()
        .and_then(|micros| i128::from(micros).checked_mul(NANOS_PER_MICRO))
        .and_then(|nanos| OffsetDateTime::from_unix_timestamp_nanos(nanos).ok())
        .map(|time| {
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
                time.year(),
                u8::from(time.month()),
                time.day(),
                time.hour(),
                time.minute(),
                time.second(),
                time.microsecond(),
            )
        })
        .ok_or(InvalidEventEnvelope::Timestamp)
}

/// The JSON object of event fields, keyed by field name.
fn object(data: &EventData) -> Map<String, Value> {
    data.fields()
        .iter()
        .map(|(name, value)| (name.clone(), json(value)))
        .collect()
}

/// The JSON value of one event value.
fn json(value: &EventValue) -> Value {
    match value {
        EventValue::Null => Value::Null,
        EventValue::Bool(truth) => Value::Bool(*truth),
        EventValue::Integer(number) => Value::from(*number),
        EventValue::Text(text) => Value::String(text.clone()),
        EventValue::List(items) => Value::Array(items.iter().map(json).collect()),
        EventValue::Object(fields) => Value::Object(object(fields)),
    }
}

#[cfg(test)]
mod tests;
