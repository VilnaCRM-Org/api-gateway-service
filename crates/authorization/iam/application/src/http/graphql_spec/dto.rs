//! Wire shapes of the GraphQL specification operations.
//!
//! Each one keeps its schema constraints and its validator attributes on the same field so that
//! both stay equal.

use iam_domain::{
    FlagDowngrade, InvalidIamValue, PermissionFlags, RemovedGrant, ServiceName, SpecDiff, SpecId,
    SpecStatus, WildcardGain,
};
use serde::{Deserialize, Serialize};
use shared_application::http::Violation;
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::error::IamError;
use crate::http::dto::DEFAULT_PAGE_SIZE;
use crate::query::get_graphql_spec_diff::GraphQlSpecView;
use crate::query::get_graphql_specs::{GetGraphQlSpecsQuery, GraphQlSpecPage, GraphQlSpecSummary};

/// Body of the operation that loads a GraphQL specification.
#[derive(Clone, Deserialize, ToSchema, Validate)]
#[serde(deny_unknown_fields)]
#[schema(as = LoadGraphQlSpecRequest)]
pub struct LoadGraphQlSpecRequest {
    /// The name of the service the schema belongs to: lower-case letters, digits and hyphens, at
    /// most 63 characters. The name `iam` is reserved for IAM's own schema.
    #[schema(min_length = 1, max_length = 63, example = "billing")]
    #[validate(length(
        min = 1,
        max = 63,
        message = "This value must contain between 1 and 63 characters."
    ))]
    pub service: String,
    /// The SDL document, at most 5 MiB. The directives `@iamSensitive` and `@iamAuditAlways` mark
    /// fields that are never covered by a wildcard grant or that are always audited.
    #[schema(min_length = 1, example = "type Query { invoices: [String!]! }")]
    #[validate(length(min = 1, message = "This value must not be empty."))]
    pub sdl: String,
}

impl std::fmt::Debug for LoadGraphQlSpecRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadGraphQlSpecRequest")
            .field("service", &self.service)
            .finish_non_exhaustive()
    }
}

/// The two flags of a coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = CoordinateFlags)]
pub struct CoordinateFlagsResponse {
    /// Whether a wildcard grant never covers the coordinate (`@iamSensitive`).
    pub sensitive: bool,
    /// Whether every use of the coordinate is audited (`@iamAuditAlways`).
    pub audit_always: bool,
}

impl From<PermissionFlags> for CoordinateFlagsResponse {
    fn from(flags: PermissionFlags) -> Self {
        Self {
            sensitive: flags.is_sensitive(),
            audit_always: flags.is_audit_always(),
        }
    }
}

/// A removed coordinate that roles grant by its exact key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = RemovedGrant)]
pub struct RemovedGrantResponse {
    /// The removed coordinate, `Type.field`.
    #[schema(example = "Mutation.pay")]
    pub coordinate: String,
    /// The identifiers of the roles that grant it, in order.
    pub roles: Vec<String>,
}

impl From<&RemovedGrant> for RemovedGrantResponse {
    fn from(grant: &RemovedGrant) -> Self {
        Self {
            coordinate: grant.coordinate.to_string(),
            roles: grant.roles.iter().map(ToString::to_string).collect(),
        }
    }
}

/// A wildcard grant that would cover added coordinates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = WildcardGain)]
pub struct WildcardGainResponse {
    /// The identifier of the role that holds the grant.
    pub role: String,
    /// The wildcard pattern, such as `gql:billing:Query.*`.
    #[schema(example = "gql:billing:Query.*")]
    pub pattern: String,
    /// The added coordinates the pattern would cover, in order.
    pub coordinates: Vec<String>,
}

impl From<&WildcardGain> for WildcardGainResponse {
    fn from(gain: &WildcardGain) -> Self {
        Self {
            role: gain.role.to_string(),
            pattern: gain.pattern.to_string(),
            coordinates: gain.coordinates.iter().map(ToString::to_string).collect(),
        }
    }
}

/// A coordinate that would lose a flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = FlagDowngrade)]
pub struct FlagDowngradeResponse {
    /// The coordinate, `Type.field`.
    #[schema(example = "Mutation.pay")]
    pub coordinate: String,
    /// Its flags in the active versions.
    pub before: CoordinateFlagsResponse,
    /// Its flags in the new version.
    pub after: CoordinateFlagsResponse,
}

impl From<&FlagDowngrade> for FlagDowngradeResponse {
    fn from(downgrade: &FlagDowngrade) -> Self {
        Self {
            coordinate: downgrade.coordinate.to_string(),
            before: CoordinateFlagsResponse::from(downgrade.before),
            after: CoordinateFlagsResponse::from(downgrade.after),
        }
    }
}

/// What a version changes against the union of the active versions of its service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = GraphQlSpecDiff)]
pub struct SpecDiffResponse {
    /// The coordinates the version adds, in order.
    pub added: Vec<String>,
    /// The coordinates the version removes, in order.
    pub removed: Vec<String>,
    /// The removed coordinates that roles grant by their exact key.
    pub removed_grants: Vec<RemovedGrantResponse>,
    /// The wildcard grants that would cover added coordinates.
    pub wildcard_gains: Vec<WildcardGainResponse>,
    /// The coordinates that would lose a flag.
    pub flag_downgrades: Vec<FlagDowngradeResponse>,
}

impl From<&SpecDiff> for SpecDiffResponse {
    fn from(diff: &SpecDiff) -> Self {
        Self {
            added: diff.added().iter().map(ToString::to_string).collect(),
            removed: diff.removed().iter().map(ToString::to_string).collect(),
            removed_grants: diff.removed_grants().iter().map(Into::into).collect(),
            wildcard_gains: diff.wildcard_gains().iter().map(Into::into).collect(),
            flag_downgrades: diff.flag_downgrades().iter().map(Into::into).collect(),
        }
    }
}

/// A GraphQL specification version with its diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = GraphQlSpec)]
pub struct GraphQlSpecResponse {
    /// The identifier of the version.
    #[schema(format = Uuid)]
    pub id: String,
    /// The service the schema belongs to.
    #[schema(example = "billing")]
    pub service: String,
    /// The SHA-256 hash of the SDL, in lower-case hexadecimal.
    #[schema(min_length = 64, max_length = 64)]
    pub content_hash: String,
    /// `draft`, `active` or `retired`.
    #[schema(example = "draft")]
    pub status: String,
    /// Who loaded the version, as `user:<id>`, `service:<name>` or `system:<component>`.
    pub uploaded_by: String,
    /// When the version was loaded, as an RFC 3339 UTC time.
    #[schema(format = DateTime, example = "2026-11-23T10:15:30.123456Z")]
    pub created_at: String,
    /// When the version became active.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(format = DateTime)]
    pub activated_at: Option<String>,
    /// When the version was retired.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(format = DateTime)]
    pub retired_at: Option<String>,
    /// The number of field coordinates of the schema.
    #[schema(minimum = 0)]
    pub coordinate_count: i64,
    /// What the version changes against the active versions of its service.
    pub diff: SpecDiffResponse,
}

impl From<&GraphQlSpecView> for GraphQlSpecResponse {
    fn from(view: &GraphQlSpecView) -> Self {
        let spec = &view.spec;
        let time = |time| humantime::format_rfc3339_micros(time).to_string();
        Self {
            id: spec.id.to_string(),
            service: spec.content.service.to_string(),
            content_hash: spec.content.content_hash.to_string(),
            status: spec.status.as_str().to_owned(),
            uploaded_by: spec.uploaded_by.to_string(),
            created_at: time(spec.created_at),
            activated_at: spec.activated_at.map(time),
            retired_at: spec.retired_at.map(time),
            coordinate_count: i64::try_from(view.coordinate_count).unwrap_or(i64::MAX),
            diff: SpecDiffResponse::from(&view.diff),
        }
    }
}

/// A GraphQL specification version without its diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = GraphQlSpecSummary)]
pub struct GraphQlSpecSummaryResponse {
    /// The identifier of the version.
    #[schema(format = Uuid)]
    pub id: String,
    /// The service the schema belongs to.
    #[schema(example = "billing")]
    pub service: String,
    /// The SHA-256 hash of the SDL, in lower-case hexadecimal.
    #[schema(min_length = 64, max_length = 64)]
    pub content_hash: String,
    /// `draft`, `active` or `retired`.
    #[schema(example = "draft")]
    pub status: String,
    /// Who loaded the version, as `user:<id>`, `service:<name>` or `system:<component>`.
    pub uploaded_by: String,
    /// When the version was loaded, as an RFC 3339 UTC time.
    #[schema(format = DateTime, example = "2026-11-23T10:15:30.123456Z")]
    pub created_at: String,
    /// When the version became active.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(format = DateTime)]
    pub activated_at: Option<String>,
    /// When the version was retired.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(format = DateTime)]
    pub retired_at: Option<String>,
    /// The number of field coordinates of the schema.
    #[schema(minimum = 0)]
    pub coordinate_count: i64,
    /// The SDL document; present only when the request asks for it with `includeSdl`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdl: Option<String>,
}

impl From<GraphQlSpecSummary> for GraphQlSpecSummaryResponse {
    fn from(summary: GraphQlSpecSummary) -> Self {
        let spec = &summary.spec;
        let time = |time| humantime::format_rfc3339_micros(time).to_string();
        Self {
            id: spec.id.to_string(),
            service: spec.content.service.to_string(),
            content_hash: spec.content.content_hash.to_string(),
            status: spec.status.as_str().to_owned(),
            uploaded_by: spec.uploaded_by.to_string(),
            created_at: time(spec.created_at),
            activated_at: spec.activated_at.map(time),
            retired_at: spec.retired_at.map(time),
            coordinate_count: i64::try_from(summary.coordinate_count).unwrap_or(i64::MAX),
            sdl: summary.sdl,
        }
    }
}

/// One page of GraphQL specification versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = GraphQlSpecPage)]
pub struct GraphQlSpecPageResponse {
    /// The versions of the page.
    pub items: Vec<GraphQlSpecSummaryResponse>,
    /// The `after` value of the next page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(format = Uuid)]
    pub next_cursor: Option<String>,
}

impl From<GraphQlSpecPage> for GraphQlSpecPageResponse {
    fn from(page: GraphQlSpecPage) -> Self {
        Self {
            items: page
                .specs
                .into_iter()
                .map(GraphQlSpecSummaryResponse::from)
                .collect(),
            next_cursor: page.next_after.map(|id| id.to_string()),
        }
    }
}

/// Query parameters of the version list; `limit` is signed so that a negative value is a 422, not
/// a parse error.
#[derive(Debug, Clone, Deserialize, IntoParams, Validate)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ListGraphQlSpecsParams {
    /// The largest number of versions of the page.
    #[param(minimum = 1, maximum = 100, default = 30)]
    #[validate(range(min = 1, max = 100, message = "This value must be between 1 and 100."))]
    pub limit: i32,
    /// The `nextCursor` of the previous page; absent for the first page.
    #[param(format = Uuid)]
    pub after: Option<String>,
    /// Only versions of this service.
    #[param(max_length = 63, example = "billing")]
    #[validate(length(max = 63, message = "This value must contain 63 characters or fewer."))]
    pub service: Option<String>,
    /// Only versions in this status: `draft`, `active` or `retired`.
    #[param(example = "active")]
    pub status: Option<String>,
    /// Whether each version carries its SDL; default `false`.
    pub include_sdl: bool,
}

impl Default for ListGraphQlSpecsParams {
    fn default() -> Self {
        Self {
            limit: DEFAULT_PAGE_SIZE,
            after: None,
            service: None,
            status: None,
            include_sdl: false,
        }
    }
}

impl ListGraphQlSpecsParams {
    /// The query for these parameters; call it after validation, which makes `limit` positive.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with a violation for each of `after`, `service` and `status` that
    /// does not hold a UUID, a service name or a known status.
    pub fn into_query(self) -> Result<GetGraphQlSpecsQuery, IamError> {
        let after = self.after.as_deref().map(SpecId::parse).transpose();
        let service = self.service.as_deref().map(ServiceName::new).transpose();
        let status = self.status.as_deref().map(parse_status).transpose();
        match (after, service, status) {
            (Ok(after), Ok(service), Ok(status)) => Ok(GetGraphQlSpecsQuery {
                limit: self.limit.unsigned_abs(),
                after,
                service,
                status,
                include_sdl: self.include_sdl,
            }),
            (after, service, status) => Err(IamError::Invalid(
                after
                    .err()
                    .map(|error| violation_of("after", error))
                    .into_iter()
                    .chain(service.err().map(|error| violation_of("service", error)))
                    .chain(status.err())
                    .collect(),
            )),
        }
    }
}

/// Query parameters of the read of one version.
#[derive(Debug, Clone, Default, Deserialize, IntoParams, Validate)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct GetGraphQlSpecParams {
    /// Whether the version carries its SDL; default `false`.
    pub include_sdl: bool,
}

/// The status that the text names.
fn parse_status(text: &str) -> Result<SpecStatus, Violation> {
    SpecStatus::parse(text).ok_or_else(|| Violation {
        property_path: "status".to_owned(),
        message: "This value must be draft, active or retired.".to_owned(),
        code: "choice".to_owned(),
    })
}

/// The violation of `property_path` that `error` describes.
fn violation_of(property_path: &str, error: InvalidIamValue) -> Violation {
    Violation {
        property_path: property_path.to_owned(),
        message: error.to_string(),
        code: error.code().to_owned(),
    }
}

#[cfg(test)]
mod tests;
