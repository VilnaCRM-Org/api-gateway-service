//! Rate policy repository double and rate policy fixtures of the IAM context.

use async_trait::async_trait;
use iam_domain::{
    ChangeStatement, EntityVersion, IamChange, RateFallback, RateKeyKind, RatePolicy,
    RatePolicyDraft, RatePolicyFields, RatePolicyId, RatePolicyPageQuery, RatePolicyParts,
    RatePolicyRepository, RatePolicyState, RatePolicyStatement, RepositoryError,
};

use crate::gateway_configuration::{gateway_change, random_time};
use crate::seed::TestRng;
use crate::unit_of_work::uuid_v7;

/// A stored rate policy named `name` that allows 100 requests a minute per IP address, at version
/// 1, created and updated at a random time after 2020.
///
/// # Panics
///
/// Panics when `name` is not a valid rate policy name.
#[expect(
    clippy::expect_used,
    reason = "a fixture with an invalid name is a defect of the test"
)]
pub fn rate_policy(rng: &mut TestRng, name: &str) -> RatePolicy {
    let at = random_time(rng);
    RatePolicy::restore(RatePolicyParts {
        id: RatePolicyId::from_uuid(uuid_v7(rng)),
        fields: RatePolicyFields::new(RatePolicyDraft {
            name: name.to_owned(),
            key_kind: RateKeyKind::Ip,
            limit: 100,
            period_seconds: 60,
            burst: 10,
            fallback: RateFallback::Divided,
        })
        .expect("a valid rate policy"),
        version: EntityVersion::INITIAL,
        created_at: at,
        updated_at: at,
        deleted_at: None,
    })
}

/// The state of a rate policy `id` that counts by `key_kind`, with the given `limit` per
/// `period_seconds` and `burst`, falling back to the limit divided among the pods.
///
/// # Panics
///
/// Panics when the numbers are not a valid rate policy.
#[expect(
    clippy::expect_used,
    reason = "a fixture with invalid numbers is a defect of the test"
)]
#[must_use]
pub fn rate_policy_state(
    id: RatePolicyId,
    key_kind: RateKeyKind,
    limit: i64,
    period_seconds: i64,
    burst: i64,
) -> RatePolicyState {
    RatePolicyState {
        id,
        fields: RatePolicyFields::new(RatePolicyDraft {
            name: "limit".to_owned(),
            key_kind,
            limit,
            period_seconds,
            burst,
            fallback: RateFallback::Divided,
        })
        .expect("a valid rate policy"),
        version: EntityVersion::INITIAL,
    }
}

/// A random committed change that runs `statements`.
pub fn rate_policy_change(rng: &mut TestRng, statements: Vec<RatePolicyStatement>) -> IamChange {
    gateway_change(
        rng,
        statements.into_iter().map(ChangeStatement::from).collect(),
    )
}

/// What the double answers with.
#[derive(Debug)]
enum Answer {
    Holding(Vec<RatePolicyParts>),
    Failing,
}

/// A rate policy repository that answers from memory with the rules of the port: deleted rate
/// policies are never found, and pages follow the order of the identifiers.
#[derive(Debug)]
pub struct FakeRatePolicyRepository {
    answer: Answer,
}

impl FakeRatePolicyRepository {
    /// A repository without rate policies.
    #[must_use]
    pub const fn new() -> Self {
        Self::holding(Vec::new())
    }

    /// A repository that holds the state of each rate policy.
    #[must_use]
    pub const fn holding(policies: Vec<RatePolicyParts>) -> Self {
        Self {
            answer: Answer::Holding(policies),
        }
    }

    /// A repository that answers `Unavailable`.
    #[must_use]
    pub const fn failing() -> Self {
        Self {
            answer: Answer::Failing,
        }
    }

    /// The rate policies that are not deleted, in the order of their identifiers.
    fn live(&self) -> Result<Vec<&RatePolicyParts>, RepositoryError> {
        match &self.answer {
            Answer::Holding(policies) => {
                let mut live: Vec<&RatePolicyParts> = policies
                    .iter()
                    .filter(|policy| policy.deleted_at.is_none())
                    .collect();
                live.sort_by_key(|policy| policy.id);
                Ok(live)
            }
            Answer::Failing => Err(RepositoryError::Unavailable(
                "in-memory repository failure".into(),
            )),
        }
    }
}

impl Default for FakeRatePolicyRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RatePolicyRepository for FakeRatePolicyRepository {
    async fn find_by_id(&self, id: RatePolicyId) -> Result<Option<RatePolicy>, RepositoryError> {
        Ok(self
            .live()?
            .into_iter()
            .find(|policy| policy.id == id)
            .map(|policy| RatePolicy::restore(policy.clone())))
    }

    async fn find_many(&self, ids: &[RatePolicyId]) -> Result<Vec<RatePolicy>, RepositoryError> {
        let live = self.live()?;
        Ok(ids
            .iter()
            .filter_map(|id| live.iter().find(|policy| policy.id == *id))
            .map(|policy| RatePolicy::restore((*policy).clone()))
            .collect())
    }

    async fn find_page(
        &self,
        query: &RatePolicyPageQuery,
    ) -> Result<Vec<RatePolicy>, RepositoryError> {
        let limit = usize::try_from(query.limit).unwrap_or(usize::MAX);
        Ok(self
            .live()?
            .into_iter()
            .filter(|policy| query.after.is_none_or(|after| policy.id > after))
            .take(limit)
            .map(|policy| RatePolicy::restore(policy.clone()))
            .collect())
    }
}

#[cfg(test)]
mod tests;
