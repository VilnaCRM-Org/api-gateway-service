//! Wire shapes of the GraphQL specification operations.
//!
//! Each one keeps its schema constraints and its validator attributes on the same field so that
//! both stay equal.

use iam_domain::{FlagDowngrade, PermissionFlags, RemovedGrant, SpecDiff, WildcardGain};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

use crate::query::get_graphql_spec_diff::GraphQlSpecView;

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

#[cfg(test)]
mod tests;
