//! The record that lets a write be replayed safely for 24 hours (FR-2).

use std::time::{Duration, SystemTime};

use crate::value_object::actor_ref::ActorRef;
use crate::value_object::idempotency_key::IdempotencyKey;
use crate::value_object::identifier::ChangeId;
use crate::value_object::request_digest::RequestDigest;

/// The idempotency key and the digest of the request that a write carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyRequest {
    /// The key the caller chose.
    pub key: IdempotencyKey,
    /// The digest of the canonical request.
    pub request_digest: RequestDigest,
}

/// One stored idempotency record: the key of an actor, the digest of its request and the change it
/// produced. The key is unique per actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyRecord {
    actor: ActorRef,
    request: IdempotencyRequest,
    change_id: ChangeId,
}

impl IdempotencyRecord {
    /// How long a key replays its change: 24 hours (FR-2).
    pub const WINDOW: Duration = Duration::from_hours(24);

    /// The oldest creation time of a record that still replays at `now` (by the `Clock` port):
    /// [`Self::WINDOW`] before `now`, or the Unix epoch when `now` is closer to it than that. A
    /// record created before this time is expired, and its key starts a new change.
    #[must_use]
    pub fn window_start(now: SystemTime) -> SystemTime {
        now.checked_sub(Self::WINDOW)
            .map_or(SystemTime::UNIX_EPOCH, |start| {
                start.max(SystemTime::UNIX_EPOCH)
            })
    }

    /// The change a repeat of the request with `request_digest` replays: the recorded change when
    /// the digest is the recorded one, none when the repeat carries another request under the
    /// same key.
    #[must_use]
    pub fn replay(&self, request_digest: RequestDigest) -> Option<ChangeId> {
        (self.request.request_digest == request_digest).then_some(self.change_id)
    }

    /// Records that `actor` sent `request`, which produced the change `change_id`.
    #[must_use]
    pub const fn new(actor: ActorRef, request: IdempotencyRequest, change_id: ChangeId) -> Self {
        Self {
            actor,
            request,
            change_id,
        }
    }

    /// Who sent the request.
    #[must_use]
    pub const fn actor(&self) -> &ActorRef {
        &self.actor
    }

    /// The key the caller chose.
    #[must_use]
    pub const fn key(&self) -> &IdempotencyKey {
        &self.request.key
    }

    /// The digest of the canonical request.
    #[must_use]
    pub const fn request_digest(&self) -> RequestDigest {
        self.request.request_digest
    }

    /// The change the request produced.
    #[must_use]
    pub const fn change_id(&self) -> ChangeId {
        self.change_id
    }
}

#[cfg(test)]
mod tests;
