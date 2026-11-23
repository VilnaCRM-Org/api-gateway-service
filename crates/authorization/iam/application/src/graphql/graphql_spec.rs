//! GraphQL objects and the resolver of the GraphQL specification operations.
//!
//! The resolver shares the use-case call and the response shapes of the REST handler, so both
//! transports apply one set of rules.

use async_graphql::{ComplexObject, Context, ID, InputObject, SimpleObject};
use shared_application::http::Problem;
use validator::Validate as _;

use super::{iam_problem_to_graphql_error, require_caller, state};
use crate::error::IamError;
use crate::http::dto::DEFAULT_PAGE_SIZE;
use crate::http::graphql_spec::dto::{
    CoordinateFlagsResponse, FlagDowngradeResponse, GraphQlSpecPageResponse, GraphQlSpecResponse,
    GraphQlSpecSummaryResponse, ListGraphQlSpecsParams, LoadGraphQlSpecRequest,
    RemovedGrantResponse, SpecDiffResponse, WildcardGainResponse,
};
use crate::http::graphql_spec::{
    find_graphql_spec, find_graphql_spec_diff, list_graphql_specs, load_graphql_spec, parse_spec_id,
};

/// Input of the mutation that loads a GraphQL specification.
#[derive(InputObject)]
#[graphql(name = "LoadGraphqlSpecInput")]
pub struct LoadGraphQlSpecInput {
    /// The name of the service the schema belongs to: lower-case letters, digits and hyphens, at most 63 characters; `iam` is reserved for IAM's own schema.
    pub service: String,
    /// The SDL document, at most 5 MiB.
    pub sdl: String,
}

impl std::fmt::Debug for LoadGraphQlSpecInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadGraphQlSpecInput")
            .field("service", &self.service)
            .finish_non_exhaustive()
    }
}

/// Filters of the version list.
#[derive(Debug, Default, InputObject)]
#[graphql(name = "GraphqlSpecFilter")]
pub struct GraphQlSpecFilterInput {
    /// Only versions of this service.
    pub service: Option<String>,
    /// Only versions in this status: `draft`, `active` or `retired`.
    pub status: Option<String>,
}

/// The two flags of a coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SimpleObject)]
#[graphql(name = "CoordinateFlags")]
pub struct CoordinateFlagsObject {
    /// Whether a wildcard grant never covers the coordinate (`@iamSensitive`).
    pub sensitive: bool,
    /// Whether every use of the coordinate is audited (`@iamAuditAlways`).
    pub audit_always: bool,
}

impl From<CoordinateFlagsResponse> for CoordinateFlagsObject {
    fn from(flags: CoordinateFlagsResponse) -> Self {
        Self {
            sensitive: flags.sensitive,
            audit_always: flags.audit_always,
        }
    }
}

/// A removed coordinate that roles grant by its exact key.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "RemovedGrant")]
pub struct RemovedGrantObject {
    /// The removed coordinate, `Type.field`.
    pub coordinate: String,
    /// The identifiers of the roles that grant it.
    pub roles: Vec<String>,
}

impl From<RemovedGrantResponse> for RemovedGrantObject {
    fn from(grant: RemovedGrantResponse) -> Self {
        Self {
            coordinate: grant.coordinate,
            roles: grant.roles,
        }
    }
}

/// A wildcard grant that would cover added coordinates.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "WildcardGain")]
pub struct WildcardGainObject {
    /// The identifier of the role that holds the grant.
    pub role: String,
    /// The wildcard pattern, such as `gql:billing:Query.*`.
    pub pattern: String,
    /// The added coordinates the pattern would cover.
    pub coordinates: Vec<String>,
}

impl From<WildcardGainResponse> for WildcardGainObject {
    fn from(gain: WildcardGainResponse) -> Self {
        Self {
            role: gain.role,
            pattern: gain.pattern,
            coordinates: gain.coordinates,
        }
    }
}

/// A coordinate that would lose a flag.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "FlagDowngrade")]
pub struct FlagDowngradeObject {
    /// The coordinate, `Type.field`.
    pub coordinate: String,
    /// Its flags in the active versions.
    pub before: CoordinateFlagsObject,
    /// Its flags in the new version.
    pub after: CoordinateFlagsObject,
}

impl From<FlagDowngradeResponse> for FlagDowngradeObject {
    fn from(downgrade: FlagDowngradeResponse) -> Self {
        Self {
            coordinate: downgrade.coordinate,
            before: downgrade.before.into(),
            after: downgrade.after.into(),
        }
    }
}

/// What a version changes against the union of the active versions of its service.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "GraphqlSpecDiff")]
pub struct SpecDiffObject {
    /// The coordinates the version adds.
    pub added: Vec<String>,
    /// The coordinates the version removes.
    pub removed: Vec<String>,
    /// The removed coordinates that roles grant by their exact key.
    pub removed_grants: Vec<RemovedGrantObject>,
    /// The wildcard grants that would cover added coordinates.
    pub wildcard_gains: Vec<WildcardGainObject>,
    /// The coordinates that would lose a flag.
    pub flag_downgrades: Vec<FlagDowngradeObject>,
}

impl From<SpecDiffResponse> for SpecDiffObject {
    fn from(diff: SpecDiffResponse) -> Self {
        Self {
            added: diff.added,
            removed: diff.removed,
            removed_grants: diff.removed_grants.into_iter().map(Into::into).collect(),
            wildcard_gains: diff.wildcard_gains.into_iter().map(Into::into).collect(),
            flag_downgrades: diff.flag_downgrades.into_iter().map(Into::into).collect(),
        }
    }
}

/// A GraphQL specification version with its diff.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "GraphqlSpec", complex)]
pub struct GraphQlSpecObject {
    /// The identifier of the version.
    pub id: ID,
    /// The service the schema belongs to.
    pub service: String,
    /// The SHA-256 hash of the SDL, in lower-case hexadecimal.
    pub content_hash: String,
    /// `draft`, `active` or `retired`.
    pub status: String,
    /// Who loaded the version, as `user:<id>`, `service:<name>` or `system:<component>`.
    pub uploaded_by: String,
    /// When the version was loaded, as an RFC 3339 UTC time.
    pub created_at: String,
    /// When the version became active.
    pub activated_at: Option<String>,
    /// When the version was retired.
    pub retired_at: Option<String>,
    /// The number of field coordinates of the schema.
    pub coordinate_count: i64,
    /// The diff that the operation already computed, so that the field does not read it again.
    #[graphql(skip)]
    pub loaded_diff: Option<SpecDiffObject>,
}

#[ComplexObject]
impl GraphQlSpecObject {
    /// What the version changes against the union of the active versions of its service.
    #[graphql(complexity = 100)]
    async fn diff(&self, ctx: &Context<'_>) -> async_graphql::Result<SpecDiffObject> {
        diff_field(ctx, &self.id, self.loaded_diff.as_ref())
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// The SDL document, read only when the query selects it.
    #[graphql(complexity = 500)]
    async fn sdl(&self, ctx: &Context<'_>) -> async_graphql::Result<Option<String>> {
        sdl_field(ctx, &self.id)
            .await
            .map_err(iam_problem_to_graphql_error)
    }
}

impl From<GraphQlSpecResponse> for GraphQlSpecObject {
    fn from(spec: GraphQlSpecResponse) -> Self {
        Self {
            id: ID::from(spec.id),
            service: spec.service,
            content_hash: spec.content_hash,
            status: spec.status,
            uploaded_by: spec.uploaded_by,
            created_at: spec.created_at,
            activated_at: spec.activated_at,
            retired_at: spec.retired_at,
            coordinate_count: spec.coordinate_count,
            loaded_diff: Some(SpecDiffObject::from(spec.diff)),
        }
    }
}

impl From<GraphQlSpecSummaryResponse> for GraphQlSpecObject {
    fn from(spec: GraphQlSpecSummaryResponse) -> Self {
        Self {
            id: ID::from(spec.id),
            service: spec.service,
            content_hash: spec.content_hash,
            status: spec.status,
            uploaded_by: spec.uploaded_by,
            created_at: spec.created_at,
            activated_at: spec.activated_at,
            retired_at: spec.retired_at,
            coordinate_count: spec.coordinate_count,
            loaded_diff: None,
        }
    }
}

/// One page of GraphQL specification versions.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "GraphqlSpecPage")]
pub struct GraphQlSpecPageObject {
    /// The versions of the page.
    pub items: Vec<GraphQlSpecObject>,
    /// The `after` value of the next page; null on the last page.
    pub next_cursor: Option<String>,
}

impl From<GraphQlSpecPageResponse> for GraphQlSpecPageObject {
    fn from(page: GraphQlSpecPageResponse) -> Self {
        Self {
            items: page
                .items
                .into_iter()
                .map(GraphQlSpecObject::from)
                .collect(),
            next_cursor: page.next_cursor,
        }
    }
}

/// Loads a GraphQL specification as a draft version, or returns the version that already holds the
/// same SDL.
pub(super) async fn load_graphql_spec_field(
    ctx: &Context<'_>,
    input: LoadGraphQlSpecInput,
) -> Result<GraphQlSpecObject, Problem> {
    let caller = require_caller(ctx)?;
    let request = LoadGraphQlSpecRequest {
        service: input.service,
        sdl: input.sdl,
    };
    request.validate()?;
    let loaded = load_graphql_spec(state(ctx)?, caller, request).await?;
    Ok(GraphQlSpecObject::from(GraphQlSpecResponse::from(
        &loaded.view,
    )))
}

/// The diff of a version: the one the operation already computed, or the one read now. The
/// operations that return a version have authenticated the caller already.
async fn diff_field(
    ctx: &Context<'_>,
    id: &ID,
    loaded: Option<&SpecDiffObject>,
) -> Result<SpecDiffObject, Problem> {
    if let Some(diff) = loaded {
        return Ok(diff.clone());
    }
    let view = find_graphql_spec_diff(state(ctx)?, parse_spec_id(id.as_str())?)
        .await?
        .ok_or(IamError::NotFound)?;
    Ok(SpecDiffObject::from(SpecDiffResponse::from(&view.diff)))
}

/// The SDL of a version; none when the version vanished. The operations that return a version have
/// authenticated the caller already.
async fn sdl_field(ctx: &Context<'_>, id: &ID) -> Result<Option<String>, Problem> {
    let summary = find_graphql_spec(state(ctx)?, parse_spec_id(id.as_str())?, true).await?;
    Ok(summary.and_then(|summary| summary.sdl))
}

/// Reads one version, without its SDL and its diff; none when it is unknown.
pub(super) async fn graphql_spec_field(
    ctx: &Context<'_>,
    id: &ID,
) -> Result<Option<GraphQlSpecObject>, Problem> {
    require_caller(ctx)?;
    let summary = find_graphql_spec(state(ctx)?, parse_spec_id(id.as_str())?, false).await?;
    Ok(summary.map(|summary| GraphQlSpecObject::from(GraphQlSpecSummaryResponse::from(summary))))
}

/// Reads one page of versions.
pub(super) async fn graphql_specs_field(
    ctx: &Context<'_>,
    first: Option<i32>,
    after: Option<String>,
    filter: GraphQlSpecFilterInput,
) -> Result<GraphQlSpecPageObject, Problem> {
    require_caller(ctx)?;
    let params = ListGraphQlSpecsParams {
        limit: first.unwrap_or(DEFAULT_PAGE_SIZE),
        after,
        service: filter.service,
        status: filter.status,
        include_sdl: false,
    };
    params.validate()?;
    let page = list_graphql_specs(state(ctx)?, params).await?;
    Ok(GraphQlSpecPageObject::from(GraphQlSpecPageResponse::from(
        page,
    )))
}

#[cfg(test)]
mod tests;
