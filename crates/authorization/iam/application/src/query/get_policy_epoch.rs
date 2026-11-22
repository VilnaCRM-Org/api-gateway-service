//! Reads the current policy epoch.

use std::sync::Arc;

use iam_domain::{PolicyEpoch, PolicyEpochRepository};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;

/// Asks for the current policy epoch.
#[derive(Debug, Clone, Copy)]
pub struct GetPolicyEpochQuery;

impl Query for GetPolicyEpochQuery {
    type Output = PolicyEpoch;
    type Error = IamError;
    const NAME: &'static str = "GetPolicyEpochQuery";
}

/// Handles [`GetPolicyEpochQuery`].
#[derive(Debug)]
pub struct GetPolicyEpochQueryHandler {
    repository: Arc<dyn PolicyEpochRepository>,
}

impl GetPolicyEpochQueryHandler {
    /// A handler over the repository.
    #[must_use]
    pub const fn new(repository: Arc<dyn PolicyEpochRepository>) -> Self {
        Self { repository }
    }

    async fn get(&self) -> Result<PolicyEpoch, IamError> {
        Ok(self.repository.current().await?)
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetPolicyEpochQuery> for GetPolicyEpochQueryHandler {
    async fn handle(&self, _query: GetPolicyEpochQuery) -> Result<PolicyEpoch, IamError> {
        self.get().await
    }
}

#[cfg(test)]
mod tests;
