//! The record that lets a write be replayed safely for 24 hours (FR-2).

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
