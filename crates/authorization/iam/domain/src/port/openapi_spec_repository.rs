//! `OpenAPI` specification read port (board name `OpenApiSpecRepository`).

use crate::openapi_spec::OpenApiSpec;
use crate::port::RepositoryError;
use crate::value_object::content_hash::ContentHash;
use crate::value_object::identifier::SpecId;
use crate::value_object::service_name::ServiceName;
use crate::value_object::spec_status::SpecStatus;

/// One page of versions to read: at most `limit` versions after the cursor, filtered by service
/// and status. The caller validates `limit` (1 to 100).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenApiSpecPageQuery {
    /// The largest number of versions of the page.
    pub limit: u32,
    /// The last version of the previous page; `None` for the first page.
    pub after: Option<SpecId>,
    /// Only versions of this service.
    pub service: Option<ServiceName>,
    /// Only versions in this status.
    pub status: Option<SpecStatus>,
}

/// Reads `OpenApiSpec` aggregates and their documents. Versions are written through the
/// [`IamUnitOfWork`](crate::IamUnitOfWork); no operation changes the document or the operations
/// of a stored version.
#[async_trait::async_trait]
pub trait OpenApiSpecRepository: std::fmt::Debug + Send + Sync {
    /// The version with the identifier.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_by_id(&self, id: SpecId) -> Result<Option<OpenApiSpec>, RepositoryError>;

    /// The document of the version with the identifier, read only when a caller asks for it.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails.
    async fn find_document(&self, id: SpecId) -> Result<Option<String>, RepositoryError>;

    /// The version of the service whose document has the content hash: an identical upload.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_by_content_hash(
        &self,
        service: &ServiceName,
        content_hash: &ContentHash,
    ) -> Result<Option<OpenApiSpec>, RepositoryError>;

    /// Every active version of the service; the catalogue of the service is their union.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_active(&self, service: &ServiceName)
    -> Result<Vec<OpenApiSpec>, RepositoryError>;

    /// One page of versions, in a stable order in which every matching version appears exactly
    /// once across pages.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_page(
        &self,
        query: &OpenApiSpecPageQuery,
    ) -> Result<Vec<OpenApiSpec>, RepositoryError>;
}
