//! Repository port of the idempotency records.

use std::time::SystemTime;

use crate::entity::idempotency_record::IdempotencyRecord;
use crate::port::RepositoryError;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::idempotency_key::IdempotencyKey;

/// Reads the idempotency records that the unit of work stores with each committed change.
#[async_trait::async_trait]
pub trait IdempotencyRepository: std::fmt::Debug + Send + Sync {
    /// Returns the record of the key `key` of `actor` when it was created at `since` or later,
    /// none when the actor never used the key or its record is older (expired).
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_since(
        &self,
        actor: &ActorRef,
        key: &IdempotencyKey,
        since: SystemTime,
    ) -> Result<Option<IdempotencyRecord>, RepositoryError>;
}
