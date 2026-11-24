//! Lists rate policies with cursor pagination (FR-64).

use std::sync::Arc;

use iam_domain::{RatePolicyId, RatePolicyPageQuery, RatePolicyParts, RatePolicyRepository};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;

/// The largest page of rate policies.
pub const MAX_PAGE_SIZE: u32 = 100;

/// Asks for one page of the rate policies that are not deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListRatePoliciesQuery {
    /// The largest number of rate policies of the page; a value outside 1 to [`MAX_PAGE_SIZE`] is
    /// brought into that range.
    pub limit: u32,
    /// The last rate policy of the previous page; none for the first page.
    pub after: Option<RatePolicyId>,
}

/// One page of rate policies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatePolicyPage {
    /// The rate policies of the page, in the stable order of the repository.
    pub rate_policies: Vec<RatePolicyParts>,
    /// The cursor of the next page: the last rate policy of this one; none when none follows.
    pub next_after: Option<RatePolicyId>,
}

impl Query for ListRatePoliciesQuery {
    type Output = RatePolicyPage;
    type Error = IamError;
    const NAME: &'static str = "ListRatePoliciesQuery";
}

/// Handles [`ListRatePoliciesQuery`].
///
/// It reads one rate policy more than the page holds, to know whether another page follows without
/// a second query.
#[derive(Debug)]
pub struct ListRatePoliciesQueryHandler {
    rate_policies: Arc<dyn RatePolicyRepository>,
}

impl ListRatePoliciesQueryHandler {
    /// A handler over the rate policy repository.
    #[must_use]
    pub const fn new(rate_policies: Arc<dyn RatePolicyRepository>) -> Self {
        Self { rate_policies }
    }

    async fn list(&self, query: ListRatePoliciesQuery) -> Result<RatePolicyPage, IamError> {
        let limit = query.limit.clamp(1, MAX_PAGE_SIZE);
        let read = RatePolicyPageQuery {
            limit: limit.saturating_add(1),
            after: query.after,
        };
        let mut rate_policies: Vec<RatePolicyParts> = self
            .rate_policies
            .find_page(&read)
            .await?
            .iter()
            .map(|policy| policy.parts().clone())
            .collect();
        let size = usize::try_from(limit).unwrap_or(usize::MAX);
        let next_after = rate_policies
            .get(size.saturating_sub(1))
            .filter(|_last| rate_policies.len() > size)
            .map(|last| last.id);
        rate_policies.truncate(size);
        Ok(RatePolicyPage {
            rate_policies,
            next_after,
        })
    }
}

#[async_trait::async_trait]
impl QueryHandler<ListRatePoliciesQuery> for ListRatePoliciesQueryHandler {
    async fn handle(&self, query: ListRatePoliciesQuery) -> Result<RatePolicyPage, IamError> {
        self.list(query).await
    }
}

#[cfg(test)]
mod tests;
