//! The domain events of the revocation state, published on `iam.events.v1`.

use std::time::SystemTime;

use shared_domain::{DomainEvent, Uuid};

use crate::entity::event_envelope::IamDomainEvent;
use crate::error::InvalidEventEnvelope;
use crate::micros;
use crate::revocation::revocation_source::RevocationSource;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::event_data::{EventData, EventValue};
use crate::value_object::identifier::SessionRevocationId;
use crate::value_object::session_id::SessionId;

/// Implements [`DomainEvent`] and [`IamDomainEvent`] for an event with the fields `event_id`,
/// `actor` and `occurred_at`, an inherent `aggregate` method and an inherent `event_data` method.
macro_rules! revocation_event {
    ($event:ident, $name:literal) => {
        impl $event {
            /// The type of the event on `iam.events.v1`.
            pub const NAME: &'static str = $name;
        }

        impl DomainEvent for $event {
            fn event_id(&self) -> Uuid {
                self.event_id
            }

            fn aggregate_id(&self) -> Uuid {
                self.aggregate()
            }

            fn occurred_at(&self) -> SystemTime {
                self.occurred_at
            }

            fn event_name(&self) -> &'static str {
                Self::NAME
            }
        }

        impl IamDomainEvent for $event {
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
    };
}

/// A session was revoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRevoked {
    /// The id of the event.
    pub event_id: Uuid,
    /// The identifier of the revocation record.
    pub revocation_id: SessionRevocationId,
    /// The revoked session.
    pub session: SessionId,
    /// The user the session belongs to.
    pub user: Uuid,
    /// Who caused the revocation.
    pub source: RevocationSource,
    /// Who revoked the session.
    pub actor: ActorRef,
    /// When the session was revoked.
    pub occurred_at: SystemTime,
    /// The earliest instant at which the record may be pruned.
    pub prune_after: SystemTime,
}

revocation_event!(SessionRevoked, "iam.session.revoked");

impl SessionRevoked {
    /// The revocation record is the aggregate.
    const fn aggregate(&self) -> Uuid {
        self.revocation_id.as_uuid()
    }

    /// `revocationId`, `sessionId`, `userId`, `source` and `pruneAfter`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        EventData::new()
            .with("revocationId", text(&self.revocation_id))?
            .with("sessionId", text(&self.session))?
            .with("userId", text(&self.user))?
            .with("source", EventValue::Text(self.source.as_str().to_owned()))?
            .with("pruneAfter", instant(self.prune_after)?)
    }
}

/// A user's tokens were cut off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserTokensCutOff {
    /// The id of the event.
    pub event_id: Uuid,
    /// The user whose tokens are cut off.
    pub user: Uuid,
    /// Tokens issued at or before this instant are refused.
    pub tokens_valid_after: SystemTime,
    /// Who caused the cut-off.
    pub source: RevocationSource,
    /// Who set the cut-off.
    pub actor: ActorRef,
    /// When the cut-off was set.
    pub occurred_at: SystemTime,
    /// The earliest instant at which the record may be pruned.
    pub prune_after: SystemTime,
}

revocation_event!(UserTokensCutOff, "iam.user_tokens.cut_off");

impl UserTokensCutOff {
    /// The user is the aggregate.
    const fn aggregate(&self) -> Uuid {
        self.user
    }

    /// `userId`, `tokensValidAfter`, `source` and `pruneAfter`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        EventData::new()
            .with("userId", text(&self.user))?
            .with("tokensValidAfter", instant(self.tokens_valid_after)?)?
            .with("source", EventValue::Text(self.source.as_str().to_owned()))?
            .with("pruneAfter", instant(self.prune_after)?)
    }
}

/// The global token cut-off was set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalTokensCutOff {
    /// The id of the event; the global cut-off has no aggregate of its own, so it is also the
    /// aggregate id.
    pub event_id: Uuid,
    /// Tokens issued at or before this instant are refused.
    pub tokens_valid_after: SystemTime,
    /// Who set the cut-off.
    pub actor: ActorRef,
    /// When the cut-off was set.
    pub occurred_at: SystemTime,
}

revocation_event!(GlobalTokensCutOff, "iam.global_tokens.cut_off");

impl GlobalTokensCutOff {
    /// The event stands for itself.
    const fn aggregate(&self) -> Uuid {
        self.event_id
    }

    /// `tokensValidAfter`.
    fn event_data(&self) -> Result<EventData, InvalidEventEnvelope> {
        EventData::new().with("tokensValidAfter", instant(self.tokens_valid_after)?)
    }
}

fn text(value: &impl std::fmt::Display) -> EventValue {
    EventValue::Text(value.to_string())
}

/// A time in whole microseconds since 1970.
fn instant(time: SystemTime) -> Result<EventValue, InvalidEventEnvelope> {
    micros::since_epoch(time)
        .map(EventValue::Integer)
        .ok_or(InvalidEventEnvelope::Timestamp)
}

#[cfg(test)]
mod tests;
