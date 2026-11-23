//! Reads one REST catalogue entry (FR-1, FR-37).

use iam_domain::PermissionId;
use shared_domain::{Query, QueryHandler};

use super::get_rest_permissions::{RestPermissionReads, RestPermissionView, describe};
use crate::error::IamError;

/// Asks for the entry with the identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetRestPermissionQuery {
    /// The entry to read.
    pub id: PermissionId,
}

impl Query for GetRestPermissionQuery {
    type Output = Option<RestPermissionView>;
    type Error = IamError;
    const NAME: &'static str = "GetRestPermissionQuery";
}

/// Handles [`GetRestPermissionQuery`]: the entry with its versions and roles, or none when it is
/// unknown.
#[derive(Debug)]
pub struct GetRestPermissionQueryHandler {
    reads: RestPermissionReads,
}

impl GetRestPermissionQueryHandler {
    /// A handler over the repositories of the catalogue, the versions and the roles.
    #[must_use]
    pub const fn new(reads: RestPermissionReads) -> Self {
        Self { reads }
    }

    async fn get(
        &self,
        query: GetRestPermissionQuery,
    ) -> Result<Option<RestPermissionView>, IamError> {
        let Some(entry) = self.reads.permissions.find_by_id(query.id).await? else {
            return Ok(None);
        };
        Ok(describe(&self.reads, &[entry]).await?.into_iter().next())
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetRestPermissionQuery> for GetRestPermissionQueryHandler {
    async fn handle(
        &self,
        query: GetRestPermissionQuery,
    ) -> Result<Option<RestPermissionView>, IamError> {
        self.get(query).await
    }
}

#[cfg(test)]
mod tests;
