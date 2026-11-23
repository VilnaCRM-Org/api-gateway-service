//! Lists role assignments with cursor pagination and filters (FR-27).

use std::collections::HashMap;
use std::sync::Arc;

use iam_domain::{
    ProjectId, RoleId, RoleName, RoleRepository, SubjectKind, UserRoleId, UserRolePageQuery,
    UserRoleRepository,
};
use shared_domain::{Clock, Query, QueryHandler};

use super::get_user_role::UserRoleView;
use crate::error::IamError;

/// The largest page of assignments.
pub const MAX_PAGE_SIZE: u32 = 100;

/// Asks for one page of the assignments that are not revoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListUserRolesQuery {
    /// The largest number of assignments of the page; a value outside 1 to [`MAX_PAGE_SIZE`] is
    /// brought into that range.
    pub limit: u32,
    /// The last assignment of the previous page; none for the first page.
    pub after: Option<UserRoleId>,
    /// Only assignments of subjects of this kind.
    pub subject_kind: Option<SubjectKind>,
    /// Only assignments of the subject with this id.
    pub subject_id: Option<String>,
    /// Only assignments of this role.
    pub role_id: Option<RoleId>,
    /// Only assignments scoped to this project.
    pub project_id: Option<ProjectId>,
    /// Whether assignments that have expired are listed as well.
    pub include_expired: bool,
}

/// One page of assignments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRolePage {
    /// The assignments of the page, in the stable order of the repository.
    pub user_roles: Vec<UserRoleView>,
    /// The cursor of the next page: the last assignment of this one; none when none follows.
    pub next_after: Option<UserRoleId>,
}

impl Query for ListUserRolesQuery {
    type Output = UserRolePage;
    type Error = IamError;
    const NAME: &'static str = "ListUserRolesQuery";
}

/// Handles [`ListUserRolesQuery`].
///
/// It reads one assignment more than the page holds, to know whether another page follows without
/// a second query, and reads the name of each distinct role of the page once.
#[derive(Debug)]
pub struct ListUserRolesQueryHandler {
    user_roles: Arc<dyn UserRoleRepository>,
    roles: Arc<dyn RoleRepository>,
    clock: Arc<dyn Clock>,
}

impl ListUserRolesQueryHandler {
    /// A handler over the assignment repository, the role repository and the clock that judges
    /// expiry.
    #[must_use]
    pub const fn new(
        user_roles: Arc<dyn UserRoleRepository>,
        roles: Arc<dyn RoleRepository>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            user_roles,
            roles,
            clock,
        }
    }

    async fn list(&self, query: ListUserRolesQuery) -> Result<UserRolePage, IamError> {
        let limit = query.limit.clamp(1, MAX_PAGE_SIZE);
        let read = UserRolePageQuery {
            limit: limit.saturating_add(1),
            after: query.after,
            subject_kind: query.subject_kind,
            subject_id: query.subject_id,
            role_id: query.role_id,
            project_id: query.project_id,
            include_expired: query.include_expired,
            now: self.clock.now(),
        };
        let mut found: Vec<_> = self
            .user_roles
            .find_page(&read)
            .await?
            .iter()
            .map(|user_role| user_role.parts().clone())
            .collect();
        let size = usize::try_from(limit).unwrap_or(usize::MAX);
        let next_after = found
            .get(size.saturating_sub(1))
            .filter(|_last| found.len() > size)
            .map(|last| last.id);
        found.truncate(size);
        let mut names: HashMap<RoleId, Option<RoleName>> = HashMap::new();
        let mut user_roles = Vec::with_capacity(found.len());
        for user_role in found {
            let role_name = self.role_name(&mut names, user_role.role_id).await?;
            user_roles.push(UserRoleView {
                user_role,
                role_name,
            });
        }
        Ok(UserRolePage {
            user_roles,
            next_after,
        })
    }

    /// The name of the role, read once and then remembered in `names`.
    async fn role_name(
        &self,
        names: &mut HashMap<RoleId, Option<RoleName>>,
        id: RoleId,
    ) -> Result<Option<RoleName>, IamError> {
        if let Some(name) = names.get(&id) {
            return Ok(name.clone());
        }
        let name = self
            .roles
            .find_by_id(id)
            .await?
            .map(|role| role.parts().name.clone());
        names.insert(id, name.clone());
        Ok(name)
    }
}

#[async_trait::async_trait]
impl QueryHandler<ListUserRolesQuery> for ListUserRolesQueryHandler {
    async fn handle(&self, query: ListUserRolesQuery) -> Result<UserRolePage, IamError> {
        self.list(query).await
    }
}

#[cfg(test)]
mod tests;
