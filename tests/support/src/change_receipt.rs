//! Change receipt repository double and receipt fixtures of the IAM context.

use async_trait::async_trait;
use iam_domain::{
    ActorRef, AuditTarget, ChangeId, ChangeReceipt, ChangeReceiptRepository, EntityVersion,
    PolicyVersion, RepositoryError,
};
use rand::RngExt as _;

use crate::seed::TestRng;
use crate::unit_of_work::uuid_v7;

/// A receipt of a random change of a role by a random user, with a policy version.
///
/// # Panics
///
/// Never in practice: the generated values satisfy the invariants.
#[expect(
    clippy::expect_used,
    reason = "the generated values satisfy the invariants; a failure is a defect of the fixture"
)]
pub fn change_receipt(rng: &mut TestRng) -> ChangeReceipt {
    let target_id = uuid_v7(rng).to_string();
    ChangeReceipt::new(
        ChangeId::from_uuid(uuid_v7(rng)),
        ActorRef::User(uuid_v7(rng)),
        AuditTarget::new("role", &target_id).expect("a role target"),
        EntityVersion::new(rng.rng().random_range(1..1_000)).expect("a version"),
        PolicyVersion::new(rng.rng().random_range(1..1_000_000)).ok(),
    )
}

/// What the double answers with.
#[derive(Debug)]
enum Answer {
    Holding(Vec<ChangeReceipt>),
    Failing,
}

/// A change receipt repository that answers from memory.
#[derive(Debug)]
pub struct FakeChangeReceiptRepository {
    answer: Answer,
}

impl FakeChangeReceiptRepository {
    /// A repository without receipts: every lookup is `NotFound`.
    #[must_use]
    pub const fn new() -> Self {
        Self::holding(Vec::new())
    }

    /// A repository that holds `receipts`.
    #[must_use]
    pub const fn holding(receipts: Vec<ChangeReceipt>) -> Self {
        Self {
            answer: Answer::Holding(receipts),
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

impl Default for FakeChangeReceiptRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChangeReceiptRepository for FakeChangeReceiptRepository {
    async fn find(&self, change_id: ChangeId) -> Result<ChangeReceipt, RepositoryError> {
        match &self.answer {
            Answer::Holding(receipts) => receipts
                .iter()
                .find(|receipt| receipt.change_id() == change_id)
                .cloned()
                .ok_or(RepositoryError::NotFound),
            Answer::Failing => Err(RepositoryError::Unavailable(
                "in-memory repository failure".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests;
