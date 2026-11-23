//! Loads the catalogue of a service for the decision path.

use std::sync::Arc;

use iam_domain::{PolicyReadRepository, ServiceCatalog, ServiceName};

use crate::error::IamError;

/// Loads the active REST operations and GraphQL type graphs of a service with the policy version
/// of the snapshot they were read in.
#[derive(Debug)]
pub struct ServiceCatalogLoader {
    policy: Arc<dyn PolicyReadRepository>,
}

impl ServiceCatalogLoader {
    /// A loader over the policy read repository.
    #[must_use]
    pub const fn new(policy: Arc<dyn PolicyReadRepository>) -> Self {
        Self { policy }
    }

    /// The catalogue of `service`; `None` when the service has no active version, which the
    /// decision path maps to `unknown_service`.
    ///
    /// # Errors
    ///
    /// [`IamError::Storage`] when the policy cannot be read; the decision path fails closed on it.
    pub async fn load(&self, service: &ServiceName) -> Result<Option<ServiceCatalog>, IamError> {
        Ok(self.policy.read_service_catalog(service).await?)
    }
}

#[cfg(test)]
mod tests;
