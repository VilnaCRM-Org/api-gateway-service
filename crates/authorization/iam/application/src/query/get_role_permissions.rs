//! Reads the grants of one role (FR-24).

use std::sync::Arc;

use iam_domain::{EntityVersion, RoleGrant, RoleId, RoleRepository};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;

/// Asks for the grants of the role with the identifier.
#[derive(Debug, Clone, Copy)]
pub struct GetRolePermissionsQuery {
    /// The role to read.
    pub id: RoleId,
}

/// The grants of a role with the version of the role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolePermissions {
    /// The role.
    pub id: RoleId,
    /// The version of the role, which an update of the grants must name.
    pub version: EntityVersion,
    /// The grants with their active flag, in key order.
    pub grants: Vec<RoleGrant>,
}

impl Query for GetRolePermissionsQuery {
    type Output = Option<RolePermissions>;
    type Error = IamError;
    const NAME: &'static str = "GetRolePermissionsQuery";
}

/// Handles [`GetRolePermissionsQuery`]: the grants of the role, or none when it is unknown or
/// deleted.
#[derive(Debug)]
pub struct GetRolePermissionsQueryHandler {
    roles: Arc<dyn RoleRepository>,
}

impl GetRolePermissionsQueryHandler {
    /// A handler over the role repository.
    #[must_use]
    pub const fn new(roles: Arc<dyn RoleRepository>) -> Self {
        Self { roles }
    }

    async fn get(
        &self,
        query: GetRolePermissionsQuery,
    ) -> Result<Option<RolePermissions>, IamError> {
        let Some(role) = self.roles.find_by_id(query.id).await? else {
            return Ok(None);
        };
        let grants = self.roles.find_grants(query.id).await?;
        Ok(Some(RolePermissions {
            id: query.id,
            version: role.parts().version,
            grants,
        }))
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetRolePermissionsQuery> for GetRolePermissionsQueryHandler {
    async fn handle(
        &self,
        query: GetRolePermissionsQuery,
    ) -> Result<Option<RolePermissions>, IamError> {
        self.get(query).await
    }
}

#[cfg(test)]
mod tests;
