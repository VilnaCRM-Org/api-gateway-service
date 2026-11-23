//! Reads an `OpenAPI` specification version with its difference from the active versions (FR-35).

use std::sync::Arc;

use iam_domain::{
    OpenApiSpecParts, OpenApiSpecRepository, RestOperationSet, RestSpecDiff, RoleGrants,
    RoleRepository, SpecId,
};
use shared_domain::{Query, QueryHandler};

use super::get_graphql_spec_diff::all_roles;
use crate::error::IamError;

/// Asks for the version with the identifier and its diff.
#[derive(Debug, Clone, Copy)]
pub struct GetOpenApiSpecDiffQuery {
    /// The version to read.
    pub id: SpecId,
}

/// A version with what it changes against the active versions of its service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenApiSpecView {
    /// The state of the version.
    pub spec: OpenApiSpecParts,
    /// The number of operations of the version.
    pub operation_count: usize,
    /// The operations the version adds and removes, the grants it affects and the flags it
    /// downgrades, compared with the union of the active versions of the service.
    pub diff: RestSpecDiff,
}

impl Query for GetOpenApiSpecDiffQuery {
    type Output = Option<OpenApiSpecView>;
    type Error = IamError;
    const NAME: &'static str = "GetOpenApiSpecDiffQuery";
}

/// Handles [`GetOpenApiSpecDiffQuery`]: the version and its diff, or none when the version is
/// unknown.
#[derive(Debug)]
pub struct GetOpenApiSpecDiffQueryHandler {
    specs: Arc<dyn OpenApiSpecRepository>,
    roles: Arc<dyn RoleRepository>,
}

impl GetOpenApiSpecDiffQueryHandler {
    /// A handler over the specification repository and the role repository.
    #[must_use]
    pub const fn new(
        specs: Arc<dyn OpenApiSpecRepository>,
        roles: Arc<dyn RoleRepository>,
    ) -> Self {
        Self { specs, roles }
    }

    async fn get(
        &self,
        query: GetOpenApiSpecDiffQuery,
    ) -> Result<Option<OpenApiSpecView>, IamError> {
        let Some(spec) = self.specs.find_by_id(query.id).await? else {
            return Ok(None);
        };
        let parts = spec.parts().clone();
        let candidate = spec.operations();
        let active = self.active_operations(&parts).await?;
        let roles = all_roles(self.roles.as_ref()).await?;
        let grants: Vec<RoleGrants<'_>> = roles
            .iter()
            .map(|role| RoleGrants {
                role: role.parts().id,
                grants: &role.parts().grants,
            })
            .collect();
        let diff = RestSpecDiff::compute(&parts.content.service, candidate, &active, &grants);
        Ok(Some(OpenApiSpecView {
            operation_count: candidate.len(),
            spec: parts,
            diff,
        }))
    }

    /// The union of the operations of the active versions of the service of `spec`.
    async fn active_operations(
        &self,
        spec: &OpenApiSpecParts,
    ) -> Result<RestOperationSet, IamError> {
        let active = self.specs.find_active(&spec.content.service).await?;
        Ok(active.iter().fold(RestOperationSet::new(), |set, version| {
            set.union(version.operations())
        }))
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetOpenApiSpecDiffQuery> for GetOpenApiSpecDiffQueryHandler {
    async fn handle(
        &self,
        query: GetOpenApiSpecDiffQuery,
    ) -> Result<Option<OpenApiSpecView>, IamError> {
        self.get(query).await
    }
}

#[cfg(test)]
mod tests;
