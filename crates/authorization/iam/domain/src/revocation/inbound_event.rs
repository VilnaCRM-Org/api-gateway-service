//! The idempotency record of one consumed User service event.

use std::time::SystemTime;

use shared_domain::Uuid;

use crate::error::InvalidIamValue;

/// What the consumer did with an event, stored as `applied`, `ignored` or `dead_letter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InboundOutcome {
    /// The event changed the revocation state.
    Applied,
    /// The event type is unknown and was skipped.
    Ignored,
    /// The record could not be decoded and was skipped.
    DeadLetter,
}

impl InboundOutcome {
    /// The stored text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Ignored => "ignored",
            Self::DeadLetter => "dead_letter",
        }
    }

    /// Parses the stored text form.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::InboundOutcome`] for any other text.
    pub fn parse(value: &str) -> Result<Self, InvalidIamValue> {
        match value {
            "applied" => Ok(Self::Applied),
            "ignored" => Ok(Self::Ignored),
            "dead_letter" => Ok(Self::DeadLetter),
            _ => Err(InvalidIamValue::InboundOutcome),
        }
    }
}

/// One consumed event, recorded once per event id so that a redelivery is not applied twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundEvent {
    /// The event id, unique per event.
    pub event_id: Uuid,
    /// The topic it was read from.
    pub topic: String,
    /// The partition it was read from.
    pub partition: i32,
    /// Its offset in the partition.
    pub offset: i64,
    /// The event type as received.
    pub event_type: String,
    /// What the consumer did with it.
    pub outcome: InboundOutcome,
    /// Why a dead letter could not be decoded; never a credential.
    pub error: Option<String>,
    /// When it was processed.
    pub processed_at: SystemTime,
}

#[cfg(test)]
mod tests;
