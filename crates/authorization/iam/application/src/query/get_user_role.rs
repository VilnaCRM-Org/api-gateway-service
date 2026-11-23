//! Reads one role assignment by its identifier (FR-27).

use std::sync::Arc;

use iam_domain::{RoleName, RoleRepository, UserRoleId, UserRoleParts, UserRoleRepository};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;

/// An assignment with the name of the role it assigns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRoleView {
    /// The state of the assignment.
    pub user_role: UserRoleParts,
    /// The name of the assigned role; none when the role is no longer stored, which only a read
    /// that races a role deletion sees.
    pub role_name: Option<RoleName>,
}

/// Asks for the assignment with the identifier.
#[derive(Debug, Clone, Copy)]
pub struct GetUserRoleQuery {
    /// The assignment to read.
    pub id: UserRoleId,
}

impl Query for GetUserRoleQuery {
    type Output = Option<UserRoleView>;
    type Error = IamError;
    const NAME: &'static str = "GetUserRoleQuery";
}

/// Handles [`GetUserRoleQuery`]: the assignment with its role name, or none when it is unknown or
/// revoked. An assignment that has expired is still answered.
#[derive(Debug)]
pub struct GetUserRoleQueryHandler {
    user_roles: Arc<dyn UserRoleRepository>,
    roles: Arc<dyn RoleRepository>,
}

impl GetUserRoleQueryHandler {
    /// A handler over the assignment repository and the role repository.
    #[must_use]
    pub const fn new(
        user_roles: Arc<dyn UserRoleRepository>,
        roles: Arc<dyn RoleRepository>,
    ) -> Self {
        Self { user_roles, roles }
    }

    async fn get(&self, query: GetUserRoleQuery) -> Result<Option<UserRoleView>, IamError> {
        let Some(user_role) = self.user_roles.find_by_id(query.id).await? else {
            return Ok(None);
        };
        let user_role = user_role.parts().clone();
        let role_name = self
            .roles
            .find_by_id(user_role.role_id)
            .await?
            .map(|role| role.parts().name.clone());
        Ok(Some(UserRoleView {
            user_role,
            role_name,
        }))
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetUserRoleQuery> for GetUserRoleQueryHandler {
    async fn handle(&self, query: GetUserRoleQuery) -> Result<Option<UserRoleView>, IamError> {
        self.get(query).await
    }
}

#[cfg(test)]
mod tests;
