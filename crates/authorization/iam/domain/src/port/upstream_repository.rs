//! Upstream read port (board name `UpstreamRepository`).

use crate::port::RepositoryError;
use crate::upstream::Upstream;
use crate::value_object::identifier::UpstreamId;
use crate::value_object::upstream_name::UpstreamName;

/// One page of upstreams to read: at most `limit` upstreams after the cursor. The caller validates
/// `limit` (1 to 100).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamPageQuery {
    /// The largest number of upstreams of the page.
    pub limit: u32,
    /// The last upstream of the previous page; `None` for the first page.
    pub after: Option<UpstreamId>,
}

/// Reads `Upstream` aggregates. Upstreams are written through the
/// [`IamUnitOfWork`](crate::IamUnitOfWork), as statements of an administrative change.
#[async_trait::async_trait]
pub trait UpstreamRepository: std::fmt::Debug + Send + Sync {
    /// The upstream with the identifier, unless it is unknown or deleted.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_by_id(&self, id: UpstreamId) -> Result<Option<Upstream>, RepositoryError>;

    /// The upstream with the name, unless it is unknown or deleted.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_by_name(&self, name: &UpstreamName) -> Result<Option<Upstream>, RepositoryError>;

    /// One page of upstreams that are not deleted, in a stable order in which every upstream
    /// appears exactly once across pages.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_page(&self, query: &UpstreamPageQuery) -> Result<Vec<Upstream>, RepositoryError>;
}
