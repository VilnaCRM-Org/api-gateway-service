//! Reads the effective permissions of a user (FR-39): the keys and wildcards its active
//! assignments hold, with the roles and scopes behind them.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use iam_domain::{
    EffectivePermissionComposer, EffectivePermissionFilter, PolicyReadRepository, ProjectId,
    RoleId, RoleName, RoleRepository, ServiceName, SubjectRef, UserRolePermission,
};
use shared_domain::{Clock, Query, QueryHandler};

use crate::error::IamError;

/// Asks for the effective permissions of a user, narrowed by an optional project and service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetUserRolePermissionsQuery {
    /// The user whose permissions are read.
    pub subject: SubjectRef,
    /// Only assignments that apply in this project: the global ones and those of the project.
    pub project: Option<ProjectId>,
    /// Only keys and wildcards of this service.
    pub service: Option<ServiceName>,
}

/// The effective permissions of a user with the names of the roles behind them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRolePermissionsView {
    /// The subject whose permissions these are.
    pub subject: SubjectRef,
    /// The read model, stamped with the policy version it was composed at.
    pub read_model: UserRolePermission,
    /// The name of every role that appears in the read model; a role that is no longer stored,
    /// which only a read that races a role deletion sees, has none.
    pub role_names: BTreeMap<RoleId, Option<RoleName>>,
}

impl Query for GetUserRolePermissionsQuery {
    type Output = UserRolePermissionsView;
    type Error = IamError;
    const NAME: &'static str = "GetUserRolePermissionsQuery";
}

/// Handles [`GetUserRolePermissionsQuery`].
///
/// It reads the policy of the user from PostgreSQL in one snapshot and composes the read model with
/// the same rule data the decision path uses, so the answer never disagrees with a decision
/// (ADR 0020). A user without assignments holds nothing, which is an empty list and not an error.
#[derive(Debug)]
pub struct GetUserRolePermissionsQueryHandler {
    policy: Arc<dyn PolicyReadRepository>,
    roles: Arc<dyn RoleRepository>,
    clock: Arc<dyn Clock>,
}

impl GetUserRolePermissionsQueryHandler {
    /// A handler over the policy read repository, the role repository that names the roles and
    /// the clock that judges expiry.
    #[must_use]
    pub const fn new(
        policy: Arc<dyn PolicyReadRepository>,
        roles: Arc<dyn RoleRepository>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            policy,
            roles,
            clock,
        }
    }

    async fn get(
        &self,
        query: GetUserRolePermissionsQuery,
    ) -> Result<UserRolePermissionsView, IamError> {
        let GetUserRolePermissionsQuery {
            subject,
            project,
            service,
        } = query;
        let policy = self.policy.read_subject_policy(&subject).await?;
        let read_model = EffectivePermissionComposer::compose(
            policy.policy_version(),
            policy.assignments(),
            policy.role_sets(),
            &EffectivePermissionFilter { project, service },
            self.clock.now(),
        );
        let role_ids: BTreeSet<RoleId> = read_model
            .permissions()
            .iter()
            .flat_map(|permission| permission.roles().iter().copied())
            .collect();
        let mut role_names = BTreeMap::new();
        for role_id in role_ids {
            let name = self
                .roles
                .find_by_id(role_id)
                .await?
                .map(|role| role.parts().name.clone());
            role_names.insert(role_id, name);
        }
        Ok(UserRolePermissionsView {
            subject,
            read_model,
            role_names,
        })
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetUserRolePermissionsQuery> for GetUserRolePermissionsQueryHandler {
    async fn handle(
        &self,
        query: GetUserRolePermissionsQuery,
    ) -> Result<UserRolePermissionsView, IamError> {
        self.get(query).await
    }
}

#[cfg(test)]
mod tests;
