//! Rate policy read port (board name `RatePolicyRepository`).

use crate::port::RepositoryError;
use crate::rate_policy::RatePolicy;
use crate::value_object::identifier::RatePolicyId;

/// One page of rate policies to read: at most `limit` policies after the cursor. The caller
/// validates `limit` (1 to 100).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatePolicyPageQuery {
    /// The largest number of rate policies of the page.
    pub limit: u32,
    /// The last rate policy of the previous page; `None` for the first page.
    pub after: Option<RatePolicyId>,
}

/// Reads `RatePolicy` aggregates. Rate policies are written through the
/// [`IamUnitOfWork`](crate::IamUnitOfWork), as statements of an administrative change.
#[async_trait::async_trait]
pub trait RatePolicyRepository: std::fmt::Debug + Send + Sync {
    /// The rate policy with the identifier, unless it is unknown or deleted.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_by_id(&self, id: RatePolicyId) -> Result<Option<RatePolicy>, RepositoryError>;

    /// The rate policies with the identifiers that exist and are not deleted, in the order of
    /// `ids`; an unknown or deleted identifier is left out.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_many(&self, ids: &[RatePolicyId]) -> Result<Vec<RatePolicy>, RepositoryError>;

    /// One page of rate policies that are not deleted, in a stable order in which every policy
    /// appears exactly once across pages.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_page(
        &self,
        query: &RatePolicyPageQuery,
    ) -> Result<Vec<RatePolicy>, RepositoryError>;
}
