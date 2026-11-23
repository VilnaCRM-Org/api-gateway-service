//! Policy reads of the decision path (board name `PolicyReadRepository`).

use crate::policy::service_catalog::ServiceCatalog;
use crate::policy::subject_policy::SubjectPolicy;
use crate::port::RepositoryError;
use crate::value_object::service_name::ServiceName;
use crate::value_object::subject::SubjectRef;

/// Reads the data of a decision together with the policy version it belongs to.
///
/// Each method reads everything it returns in one consistent snapshot, so the data and the stamp
/// are either both before or both after a concurrent write.
#[async_trait::async_trait]
pub trait PolicyReadRepository: std::fmt::Debug + Send + Sync {
    /// The assignments of the subject that are not revoked, the compiled sets of their roles
    /// (active grants only: orphaned grants are left out) and the current policy epoch.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::NotFound`] when the policy epoch row is missing, and
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn read_subject_policy(
        &self,
        subject: &SubjectRef,
    ) -> Result<SubjectPolicy, RepositoryError>;

    /// The active REST operations and GraphQL type graphs of the service with the current policy
    /// epoch; `None` when the service has no active version of either kind.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::NotFound`] when the policy epoch row is missing, and
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn read_service_catalog(
        &self,
        service: &ServiceName,
    ) -> Result<Option<ServiceCatalog>, RepositoryError>;
}
