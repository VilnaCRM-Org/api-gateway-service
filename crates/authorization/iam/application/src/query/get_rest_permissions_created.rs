//! Reads the keys that the activation of an `OpenAPI` version created.

use std::sync::Arc;

use iam_domain::{PermissionKey, RestPermissionRepository, SpecId};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;

/// Asks for the keys that the activation of the version `spec_id` created.
#[derive(Debug, Clone, Copy)]
pub struct GetRestPermissionsCreatedQuery {
    /// The activated version.
    pub spec_id: SpecId,
}

impl Query for GetRestPermissionsCreatedQuery {
    type Output = Vec<PermissionKey>;
    type Error = IamError;
    const NAME: &'static str = "GetRestPermissionsCreatedQuery";
}

/// Handles [`GetRestPermissionsCreatedQuery`]: the keys in key order, or none for a version
/// whose activation recorded nothing.
#[derive(Debug)]
pub struct GetRestPermissionsCreatedQueryHandler {
    permissions: Arc<dyn RestPermissionRepository>,
}

impl GetRestPermissionsCreatedQueryHandler {
    /// A handler over the catalogue repository.
    #[must_use]
    pub const fn new(permissions: Arc<dyn RestPermissionRepository>) -> Self {
        Self { permissions }
    }

    async fn find(
        &self,
        query: GetRestPermissionsCreatedQuery,
    ) -> Result<Vec<PermissionKey>, IamError> {
        Ok(self
            .permissions
            .find_created_keys(query.spec_id)
            .await?
            .unwrap_or_default())
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetRestPermissionsCreatedQuery> for GetRestPermissionsCreatedQueryHandler {
    async fn handle(
        &self,
        query: GetRestPermissionsCreatedQuery,
    ) -> Result<Vec<PermissionKey>, IamError> {
        self.find(query).await
    }
}

#[cfg(test)]
mod tests;
