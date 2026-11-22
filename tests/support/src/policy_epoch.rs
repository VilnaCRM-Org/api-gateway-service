//! Policy epoch repository double and fixtures of the IAM context.

use async_trait::async_trait;
use iam_domain::{
    LogEpoch, PolicyDigestValue, PolicyEpoch, PolicyEpochRepository, PolicyVersion, RelayEpoch,
    RepositoryError,
};
use rand::RngExt as _;

use crate::seed::TestRng;

/// The epoch the migration seeds: version 0, a digest of zeros and every epoch 0.
///
/// # Panics
///
/// Never in practice: the seeded values satisfy the invariants.
#[must_use]
pub fn seeded_policy_epoch() -> PolicyEpoch {
    epoch_of(0, [0; PolicyDigestValue::LENGTH], 0, 0, 0)
}

/// A valid epoch that differs from the seeded one: every number is 1 or greater.
///
/// # Panics
///
/// Never in practice: the generated values satisfy the invariants.
pub fn policy_epoch(rng: &mut TestRng) -> PolicyEpoch {
    let version = rng.rng().random_range(1..=i64::MAX);
    let digest: [u8; PolicyDigestValue::LENGTH] = rng.rng().random();
    let log_epoch = rng.rng().random_range(1..=i64::MAX);
    let relay_epoch = rng.rng().random_range(1..=i64::MAX);
    let catalog_epoch = rng.rng().random_range(1..=i64::MAX);
    epoch_of(version, digest, log_epoch, relay_epoch, catalog_epoch)
}

#[expect(
    clippy::expect_used,
    reason = "the callers pass values that satisfy the invariants; a failure is a defect of the fixture"
)]
fn epoch_of(
    version: i64,
    digest: [u8; PolicyDigestValue::LENGTH],
    log_epoch: i64,
    relay_epoch: i64,
    catalog_epoch: i64,
) -> PolicyEpoch {
    PolicyEpoch::new(
        PolicyVersion::new(version).expect("a non-negative policy version"),
        PolicyDigestValue::new(&digest).expect("a digest of 16 bytes"),
        LogEpoch::new(log_epoch).expect("a non-negative log epoch"),
        RelayEpoch::new(relay_epoch).expect("a non-negative relay epoch"),
        catalog_epoch,
    )
    .expect("a non-negative catalogue epoch")
}

/// What the double answers with.
#[derive(Debug, Clone, Copy)]
enum Answer {
    Holding(PolicyEpoch),
    Empty,
    Failing,
}

/// A policy epoch repository that answers from memory.
#[derive(Debug)]
pub struct FakePolicyEpochRepository {
    answer: Answer,
}

impl FakePolicyEpochRepository {
    /// A repository that holds the seeded epoch, like a freshly migrated database.
    #[must_use]
    pub fn new() -> Self {
        Self::holding(seeded_policy_epoch())
    }

    /// A repository that holds `epoch`.
    #[must_use]
    pub const fn holding(epoch: PolicyEpoch) -> Self {
        Self {
            answer: Answer::Holding(epoch),
        }
    }

    /// A repository without the epoch row: it answers `NotFound`.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            answer: Answer::Empty,
        }
    }

    /// A repository that answers `Unavailable`.
    #[must_use]
    pub const fn failing() -> Self {
        Self {
            answer: Answer::Failing,
        }
    }
}

impl Default for FakePolicyEpochRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PolicyEpochRepository for FakePolicyEpochRepository {
    async fn current(&self) -> Result<PolicyEpoch, RepositoryError> {
        match self.answer {
            Answer::Holding(epoch) => Ok(epoch),
            Answer::Empty => Err(RepositoryError::NotFound),
            Answer::Failing => Err(RepositoryError::Unavailable(
                "in-memory repository failure".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests;
