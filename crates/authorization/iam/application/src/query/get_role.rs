//! Reads one role by its identifier (FR-21).

use std::sync::Arc;

use iam_domain::{RoleId, RoleParts, RoleRepository};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;

/// Asks for the role with the identifier.
#[derive(Debug, Clone, Copy)]
pub struct GetRoleQuery {
    /// The role to read.
    pub id: RoleId,
}

impl Query for GetRoleQuery {
    type Output = Option<RoleParts>;
    type Error = IamError;
    const NAME: &'static str = "GetRoleQuery";
}

/// Handles [`GetRoleQuery`]: the state of the role, or none when it is unknown or deleted.
#[derive(Debug)]
pub struct GetRoleQueryHandler {
    roles: Arc<dyn RoleRepository>,
}

impl GetRoleQueryHandler {
    /// A handler over the role repository.
    #[must_use]
    pub const fn new(roles: Arc<dyn RoleRepository>) -> Self {
        Self { roles }
    }

    async fn get(&self, query: GetRoleQuery) -> Result<Option<RoleParts>, IamError> {
        let role = self.roles.find_by_id(query.id).await?;
        Ok(role.map(|role| role.parts().clone()))
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetRoleQuery> for GetRoleQueryHandler {
    async fn handle(&self, query: GetRoleQuery) -> Result<Option<RoleParts>, IamError> {
        self.get(query).await
    }
}

#[cfg(test)]
mod tests;
