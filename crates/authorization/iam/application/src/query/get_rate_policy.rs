//! Reads one rate policy by its identifier (FR-64).

use std::sync::Arc;

use iam_domain::{RatePolicyId, RatePolicyParts, RatePolicyRepository};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;

/// Asks for the rate policy with the identifier.
#[derive(Debug, Clone, Copy)]
pub struct GetRatePolicyQuery {
    /// The rate policy to read.
    pub id: RatePolicyId,
}

impl Query for GetRatePolicyQuery {
    type Output = Option<RatePolicyParts>;
    type Error = IamError;
    const NAME: &'static str = "GetRatePolicyQuery";
}

/// Handles [`GetRatePolicyQuery`]: the state of the rate policy, or none when it is unknown or
/// deleted.
#[derive(Debug)]
pub struct GetRatePolicyQueryHandler {
    rate_policies: Arc<dyn RatePolicyRepository>,
}

impl GetRatePolicyQueryHandler {
    /// A handler over the rate policy repository.
    #[must_use]
    pub const fn new(rate_policies: Arc<dyn RatePolicyRepository>) -> Self {
        Self { rate_policies }
    }

    async fn get(&self, query: GetRatePolicyQuery) -> Result<Option<RatePolicyParts>, IamError> {
        let policy = self.rate_policies.find_by_id(query.id).await?;
        Ok(policy.map(|policy| policy.parts().clone()))
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetRatePolicyQuery> for GetRatePolicyQueryHandler {
    async fn handle(&self, query: GetRatePolicyQuery) -> Result<Option<RatePolicyParts>, IamError> {
        self.get(query).await
    }
}

#[cfg(test)]
mod tests;
