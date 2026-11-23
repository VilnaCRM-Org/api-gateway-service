//! REST catalogue read port.

use crate::port::RepositoryError;
use crate::port::permission_page_query::PermissionPageQuery;
use crate::rest_permission::RestPermission;
use crate::value_object::identifier::{PermissionId, SpecId};
use crate::value_object::permission_key::PermissionKey;
use crate::value_object::service_name::ServiceName;

/// Reads `RestPermission` entries. Entries are written through the
/// [`IamUnitOfWork`](crate::IamUnitOfWork) together with the activation that creates them.
#[async_trait::async_trait]
pub trait RestPermissionRepository: std::fmt::Debug + Send + Sync {
    /// The entry with the identifier.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_by_id(&self, id: PermissionId)
    -> Result<Option<RestPermission>, RepositoryError>;

    /// The entries of the service whose key is one of `keys`, active or not.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_by_keys(
        &self,
        service: &ServiceName,
        keys: &[PermissionKey],
    ) -> Result<Vec<RestPermission>, RepositoryError>;

    /// Every entry of the service, active or not, in key order.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_by_service(
        &self,
        service: &ServiceName,
    ) -> Result<Vec<RestPermission>, RepositoryError>;

    /// One page of entries, in a stable order in which every matching entry appears exactly once
    /// across pages.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_page(
        &self,
        query: &PermissionPageQuery,
    ) -> Result<Vec<RestPermission>, RepositoryError>;

    /// The keys that the activation of the version created, as the activation recorded them in
    /// `iam.rest_permissions.created`; `None` when the version has no such record.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_created_keys(
        &self,
        spec_id: SpecId,
    ) -> Result<Option<Vec<PermissionKey>>, RepositoryError>;
}
