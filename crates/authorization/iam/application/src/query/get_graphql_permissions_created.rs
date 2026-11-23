//! Reads the keys that the activation of a GraphQL version created.

use std::sync::Arc;

use iam_domain::{GraphQlPermissionRepository, PermissionKey, SpecId};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;

/// Asks for the keys that the activation of the version `spec_id` created.
#[derive(Debug, Clone, Copy)]
pub struct GetGraphQlPermissionsCreatedQuery {
    /// The activated version.
    pub spec_id: SpecId,
}

impl Query for GetGraphQlPermissionsCreatedQuery {
    type Output = Vec<PermissionKey>;
    type Error = IamError;
    const NAME: &'static str = "GetGraphQlPermissionsCreatedQuery";
}

/// Handles [`GetGraphQlPermissionsCreatedQuery`]: the keys in key order, or none for a version
/// whose activation recorded nothing.
#[derive(Debug)]
pub struct GetGraphQlPermissionsCreatedQueryHandler {
    permissions: Arc<dyn GraphQlPermissionRepository>,
}

impl GetGraphQlPermissionsCreatedQueryHandler {
    /// A handler over the catalogue repository.
    #[must_use]
    pub const fn new(permissions: Arc<dyn GraphQlPermissionRepository>) -> Self {
        Self { permissions }
    }

    async fn find(
        &self,
        query: GetGraphQlPermissionsCreatedQuery,
    ) -> Result<Vec<PermissionKey>, IamError> {
        Ok(self
            .permissions
            .find_created_keys(query.spec_id)
            .await?
            .unwrap_or_default())
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetGraphQlPermissionsCreatedQuery> for GetGraphQlPermissionsCreatedQueryHandler {
    async fn handle(
        &self,
        query: GetGraphQlPermissionsCreatedQuery,
    ) -> Result<Vec<PermissionKey>, IamError> {
        self.find(query).await
    }
}

#[cfg(test)]
mod tests;
