//! Idempotency repository double and record fixtures of the IAM context.

use std::sync::{Mutex, PoisonError};
use std::time::SystemTime;

use async_trait::async_trait;
use iam_domain::{
    ActorRef, ChangeId, IdempotencyKey, IdempotencyRecord, IdempotencyRepository,
    IdempotencyRequest, RepositoryError, RequestDigest,
};
use rand::RngExt as _;

use crate::seed::TestRng;
use crate::unit_of_work::uuid_v7;

/// A request with a random key of visible ASCII and a random digest.
///
/// # Panics
///
/// Never in practice: the generated values satisfy the invariants.
#[expect(
    clippy::expect_used,
    reason = "the generated values satisfy the invariants; a failure is a defect of the fixture"
)]
pub fn idempotency_request(rng: &mut TestRng) -> IdempotencyRequest {
    let digest: [u8; RequestDigest::LENGTH] = rng.rng().random();
    let suffix: u64 = rng.rng().random();
    IdempotencyRequest {
        key: IdempotencyKey::new(&format!("key-{suffix}")).expect("a visible ASCII key"),
        request_digest: RequestDigest::new(&digest).expect("32 bytes"),
    }
}

/// A record of `request` by `actor` for a random change.
pub fn idempotency_record(
    rng: &mut TestRng,
    actor: ActorRef,
    request: IdempotencyRequest,
) -> IdempotencyRecord {
    IdempotencyRecord::new(actor, request, ChangeId::from_uuid(uuid_v7(rng)))
}

/// What the double answers with.
#[derive(Debug)]
enum Answer {
    Holding(Vec<(IdempotencyRecord, SystemTime)>),
    Failing,
}

/// An idempotency repository that answers from memory and remembers the `since` of every lookup.
#[derive(Debug)]
pub struct FakeIdempotencyRepository {
    answer: Answer,
    asked_since: Mutex<Vec<SystemTime>>,
}

impl FakeIdempotencyRepository {
    /// A repository without records: every lookup finds nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self::holding(Vec::new())
    }

    /// A repository that holds each record with the time it was created.
    #[must_use]
    pub const fn holding(records: Vec<(IdempotencyRecord, SystemTime)>) -> Self {
        Self {
            answer: Answer::Holding(records),
            asked_since: Mutex::new(Vec::new()),
        }
    }

    /// A repository that answers `Unavailable`.
    #[must_use]
    pub const fn failing() -> Self {
        Self {
            answer: Answer::Failing,
            asked_since: Mutex::new(Vec::new()),
        }
    }

    /// The `since` of every lookup, in order.
    #[must_use]
    pub fn asked_since(&self) -> Vec<SystemTime> {
        self.asked_since
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Default for FakeIdempotencyRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IdempotencyRepository for FakeIdempotencyRepository {
    async fn find_since(
        &self,
        actor: &ActorRef,
        key: &IdempotencyKey,
        since: SystemTime,
    ) -> Result<Option<IdempotencyRecord>, RepositoryError> {
        self.asked_since
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(since);
        match &self.answer {
            Answer::Holding(records) => Ok(records
                .iter()
                .find(|(record, created_at)| {
                    record.actor() == actor && record.key() == key && *created_at >= since
                })
                .map(|(record, _created_at)| record.clone())),
            Answer::Failing => Err(RepositoryError::Unavailable(
                "in-memory repository failure".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests;
