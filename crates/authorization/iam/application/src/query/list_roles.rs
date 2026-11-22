//! Lists roles with cursor pagination and filters (FR-21).

use std::sync::Arc;

use iam_domain::{RoleId, RoleKind, RolePageQuery, RoleParts, RoleRepository};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;

/// The largest page of roles.
pub const MAX_PAGE_SIZE: u32 = 100;

/// Asks for one page of the roles that are not deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListRolesQuery {
    /// The largest number of roles of the page; a value outside 1 to [`MAX_PAGE_SIZE`] is
    /// brought into that range.
    pub limit: u32,
    /// The last role of the previous page; none for the first page.
    pub after: Option<RoleId>,
    /// Only roles whose name starts with this text, compared without regard to case.
    pub name_prefix: Option<String>,
    /// Only roles of this kind.
    pub kind: Option<RoleKind>,
}

/// One page of roles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolePage {
    /// The roles of the page, in the stable order of the repository.
    pub roles: Vec<RoleParts>,
    /// The cursor of the next page: the last role of this one; none when no role follows.
    pub next_after: Option<RoleId>,
}

impl Query for ListRolesQuery {
    type Output = RolePage;
    type Error = IamError;
    const NAME: &'static str = "ListRolesQuery";
}

/// Handles [`ListRolesQuery`].
///
/// It reads one role more than the page holds, to know whether another page follows without a
/// second query.
#[derive(Debug)]
pub struct ListRolesQueryHandler {
    roles: Arc<dyn RoleRepository>,
}

impl ListRolesQueryHandler {
    /// A handler over the role repository.
    #[must_use]
    pub const fn new(roles: Arc<dyn RoleRepository>) -> Self {
        Self { roles }
    }

    async fn list(&self, query: ListRolesQuery) -> Result<RolePage, IamError> {
        let limit = query.limit.clamp(1, MAX_PAGE_SIZE);
        let read = RolePageQuery {
            limit: limit.saturating_add(1),
            after: query.after,
            name_prefix: query.name_prefix,
            kind: query.kind,
        };
        let mut roles: Vec<RoleParts> = self
            .roles
            .find_page(&read)
            .await?
            .iter()
            .map(|role| role.parts().clone())
            .collect();
        let size = usize::try_from(limit).unwrap_or(usize::MAX);
        let next_after = roles
            .get(size.saturating_sub(1))
            .filter(|_last| roles.len() > size)
            .map(|last| last.id);
        roles.truncate(size);
        Ok(RolePage { roles, next_after })
    }
}

#[async_trait::async_trait]
impl QueryHandler<ListRolesQuery> for ListRolesQueryHandler {
    async fn handle(&self, query: ListRolesQuery) -> Result<RolePage, IamError> {
        self.list(query).await
    }
}

#[cfg(test)]
mod tests;
