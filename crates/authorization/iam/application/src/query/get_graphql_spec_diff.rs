//! Reads a GraphQL specification version with its difference from the active versions (FR-31).

use std::sync::Arc;

use iam_domain::{
    CoordinateSet, GraphQlSpecParts, GraphQlSpecRepository, Role, RoleGrants, RolePageQuery,
    RoleRepository, SpecDiff, SpecId,
};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;

/// The page size with which the handler reads the roles whose grants the diff weighs.
const ROLE_PAGE_SIZE: u32 = 100;

/// Asks for the version with the identifier and its diff.
#[derive(Debug, Clone, Copy)]
pub struct GetGraphQlSpecDiffQuery {
    /// The version to read.
    pub id: SpecId,
}

/// A version with what it changes against the active versions of its service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphQlSpecView {
    /// The state of the version.
    pub spec: GraphQlSpecParts,
    /// The number of field coordinates of the version.
    pub coordinate_count: usize,
    /// The coordinates the version adds and removes, the grants it affects and the flags it
    /// downgrades, compared with the union of the active versions of the service.
    pub diff: SpecDiff,
}

impl Query for GetGraphQlSpecDiffQuery {
    type Output = Option<GraphQlSpecView>;
    type Error = IamError;
    const NAME: &'static str = "GetGraphQlSpecDiffQuery";
}

/// Handles [`GetGraphQlSpecDiffQuery`]: the version and its diff, or none when the version is
/// unknown.
#[derive(Debug)]
pub struct GetGraphQlSpecDiffQueryHandler {
    specs: Arc<dyn GraphQlSpecRepository>,
    roles: Arc<dyn RoleRepository>,
}

impl GetGraphQlSpecDiffQueryHandler {
    /// A handler over the specification repository and the role repository.
    #[must_use]
    pub const fn new(
        specs: Arc<dyn GraphQlSpecRepository>,
        roles: Arc<dyn RoleRepository>,
    ) -> Self {
        Self { specs, roles }
    }

    async fn get(
        &self,
        query: GetGraphQlSpecDiffQuery,
    ) -> Result<Option<GraphQlSpecView>, IamError> {
        let Some(spec) = self.specs.find_by_id(query.id).await? else {
            return Ok(None);
        };
        let parts = spec.parts().clone();
        let candidate = spec.coordinates();
        let active = self.active_coordinates(&parts).await?;
        let roles = self.all_roles().await?;
        let grants: Vec<RoleGrants<'_>> = roles
            .iter()
            .map(|role| RoleGrants {
                role: role.parts().id,
                grants: &role.parts().grants,
            })
            .collect();
        let diff = SpecDiff::compute(&parts.content.service, &candidate, &active, &grants);
        Ok(Some(GraphQlSpecView {
            coordinate_count: candidate.len(),
            spec: parts,
            diff,
        }))
    }

    /// The union of the coordinates of the active versions of the service of `spec`.
    async fn active_coordinates(&self, spec: &GraphQlSpecParts) -> Result<CoordinateSet, IamError> {
        let active = self.specs.find_active(&spec.content.service).await?;
        Ok(active.iter().fold(CoordinateSet::new(), |set, version| {
            set.union(&version.coordinates())
        }))
    }

    /// Every role that is not deleted, read page by page.
    async fn all_roles(&self) -> Result<Vec<Role>, IamError> {
        all_roles(self.roles.as_ref()).await
    }
}

/// Every role that is not deleted, read page by page; the diffs of both kinds of specification
/// weigh the grants of all of them.
pub(crate) async fn all_roles(roles: &dyn RoleRepository) -> Result<Vec<Role>, IamError> {
    let mut all = Vec::new();
    let mut after = None;
    loop {
        let query = RolePageQuery {
            limit: ROLE_PAGE_SIZE,
            after,
            name_prefix: None,
            kind: None,
        };
        let page = roles.find_page(&query).await?;
        let last = page.last().map(|role| role.parts().id);
        let full = u32::try_from(page.len()).is_ok_and(|length| length >= ROLE_PAGE_SIZE);
        all.extend(page);
        match last {
            Some(id) if full => after = Some(id),
            _ => return Ok(all),
        }
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetGraphQlSpecDiffQuery> for GetGraphQlSpecDiffQueryHandler {
    async fn handle(
        &self,
        query: GetGraphQlSpecDiffQuery,
    ) -> Result<Option<GraphQlSpecView>, IamError> {
        self.get(query).await
    }
}

#[cfg(test)]
mod tests;
