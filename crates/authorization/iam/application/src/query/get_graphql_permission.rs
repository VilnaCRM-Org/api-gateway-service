//! Reads one GraphQL catalogue entry (FR-1, FR-33).

use iam_domain::PermissionId;
use shared_domain::{Query, QueryHandler};

use super::get_graphql_permissions::{GraphQlPermissionView, PermissionReads, describe};
use crate::error::IamError;

/// Asks for the entry with the identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetGraphQlPermissionQuery {
    /// The entry to read.
    pub id: PermissionId,
}

impl Query for GetGraphQlPermissionQuery {
    type Output = Option<GraphQlPermissionView>;
    type Error = IamError;
    const NAME: &'static str = "GetGraphQlPermissionQuery";
}

/// Handles [`GetGraphQlPermissionQuery`]: the entry with its versions and roles, or none when it
/// is unknown.
#[derive(Debug)]
pub struct GetGraphQlPermissionQueryHandler {
    reads: PermissionReads,
}

impl GetGraphQlPermissionQueryHandler {
    /// A handler over the repositories of the catalogue, the versions and the roles.
    #[must_use]
    pub const fn new(reads: PermissionReads) -> Self {
        Self { reads }
    }

    async fn get(
        &self,
        query: GetGraphQlPermissionQuery,
    ) -> Result<Option<GraphQlPermissionView>, IamError> {
        let Some(entry) = self.reads.permissions.find_by_id(query.id).await? else {
            return Ok(None);
        };
        Ok(describe(&self.reads, &[entry]).await?.into_iter().next())
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetGraphQlPermissionQuery> for GetGraphQlPermissionQueryHandler {
    async fn handle(
        &self,
        query: GetGraphQlPermissionQuery,
    ) -> Result<Option<GraphQlPermissionView>, IamError> {
        self.get(query).await
    }
}

#[cfg(test)]
mod tests;
