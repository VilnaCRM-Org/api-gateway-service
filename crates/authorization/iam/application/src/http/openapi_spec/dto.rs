//! Wire shapes of the `OpenAPI` specification operations.
//!
//! Each one keeps its schema constraints and its validator attributes on the same field so that
//! both stay equal.

use iam_domain::{
    PermissionFlags, RemovedRestGrant, RestFlagDowngrade, RestOperationKey, RestSpecDiff,
    RestWildcardGain,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

use crate::query::get_openapi_spec_diff::OpenApiSpecView;

/// Body of the operation that loads an `OpenAPI` specification.
#[derive(Clone, Deserialize, ToSchema, Validate)]
#[serde(deny_unknown_fields)]
#[schema(as = LoadOpenApiSpecRequest)]
pub struct LoadOpenApiSpecRequest {
    /// The name of the service the document belongs to: lower-case letters, digits and hyphens, at
    /// most 63 characters. The name `iam` is reserved for IAM's own document.
    #[schema(min_length = 1, max_length = 63, example = "billing")]
    #[validate(length(
        min = 1,
        max = 63,
        message = "This value must contain between 1 and 63 characters."
    ))]
    pub service: String,
    /// The `OpenAPI` 3.0.x or 3.1.x document as JSON text, at most 5 MiB, with at most 5,000
    /// operations and internal `#/` references only. The members `x-iam-sensitive: true` and
    /// `x-iam-audit: always` of an operation mark it as never covered by a wildcard grant or as
    /// always audited.
    #[schema(
        min_length = 1,
        example = "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{}}"
    )]
    #[validate(length(min = 1, message = "This value must not be empty."))]
    pub document: String,
}

impl std::fmt::Debug for LoadOpenApiSpecRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadOpenApiSpecRequest")
            .field("service", &self.service)
            .finish_non_exhaustive()
    }
}

/// The two flags of an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = OperationFlags)]
pub struct OperationFlagsResponse {
    /// Whether a wildcard grant never covers the operation (`x-iam-sensitive`).
    pub sensitive: bool,
    /// Whether every use of the operation is audited (`x-iam-audit: always`).
    pub audit_always: bool,
}

impl From<PermissionFlags> for OperationFlagsResponse {
    fn from(flags: PermissionFlags) -> Self {
        Self {
            sensitive: flags.is_sensitive(),
            audit_always: flags.is_audit_always(),
        }
    }
}

/// The text of an operation: `{METHOD} {template}`, the tail of its permission key.
fn operation_text(operation: &RestOperationKey) -> String {
    operation.to_string()
}

/// A removed operation that roles grant by its exact key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = RemovedOperationGrant)]
pub struct RemovedOperationGrantResponse {
    /// The removed operation, `{METHOD} {template}`.
    #[schema(example = "POST /api/invoices/{}/pay")]
    pub operation: String,
    /// The identifiers of the roles that grant it, in order.
    pub roles: Vec<String>,
}

impl From<&RemovedRestGrant> for RemovedOperationGrantResponse {
    fn from(grant: &RemovedRestGrant) -> Self {
        Self {
            operation: operation_text(&grant.operation),
            roles: grant.roles.iter().map(ToString::to_string).collect(),
        }
    }
}

/// A wildcard grant that would cover added operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = OperationWildcardGain)]
pub struct OperationWildcardGainResponse {
    /// The identifier of the role that holds the grant.
    pub role: String,
    /// The wildcard pattern, such as `rest:billing:GET *`.
    #[schema(example = "rest:billing:GET *")]
    pub pattern: String,
    /// The added operations the pattern would cover, in order.
    pub operations: Vec<String>,
}

impl From<&RestWildcardGain> for OperationWildcardGainResponse {
    fn from(gain: &RestWildcardGain) -> Self {
        Self {
            role: gain.role.to_string(),
            pattern: gain.pattern.to_string(),
            operations: gain.operations.iter().map(operation_text).collect(),
        }
    }
}

/// An operation that would lose a flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = OperationFlagDowngrade)]
pub struct OperationFlagDowngradeResponse {
    /// The operation, `{METHOD} {template}`.
    #[schema(example = "POST /api/invoices/{}/pay")]
    pub operation: String,
    /// Its flags in the active versions.
    pub before: OperationFlagsResponse,
    /// Its flags in the new version.
    pub after: OperationFlagsResponse,
}

impl From<&RestFlagDowngrade> for OperationFlagDowngradeResponse {
    fn from(downgrade: &RestFlagDowngrade) -> Self {
        Self {
            operation: operation_text(&downgrade.operation),
            before: OperationFlagsResponse::from(downgrade.before),
            after: OperationFlagsResponse::from(downgrade.after),
        }
    }
}

/// What a version changes against the union of the active versions of its service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = OpenApiSpecDiff)]
pub struct RestSpecDiffResponse {
    /// The operations the version adds, in order.
    pub added: Vec<String>,
    /// The operations the version removes, in order.
    pub removed: Vec<String>,
    /// The removed operations that roles grant by their exact key.
    pub removed_grants: Vec<RemovedOperationGrantResponse>,
    /// The wildcard grants that would cover added operations.
    pub wildcard_gains: Vec<OperationWildcardGainResponse>,
    /// The operations that would lose a flag.
    pub flag_downgrades: Vec<OperationFlagDowngradeResponse>,
}

impl From<&RestSpecDiff> for RestSpecDiffResponse {
    fn from(diff: &RestSpecDiff) -> Self {
        Self {
            added: diff.added().iter().map(operation_text).collect(),
            removed: diff.removed().iter().map(operation_text).collect(),
            removed_grants: diff.removed_grants().iter().map(Into::into).collect(),
            wildcard_gains: diff.wildcard_gains().iter().map(Into::into).collect(),
            flag_downgrades: diff.flag_downgrades().iter().map(Into::into).collect(),
        }
    }
}

/// An `OpenAPI` specification version with its diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = OpenApiSpec)]
pub struct OpenApiSpecResponse {
    /// The identifier of the version.
    #[schema(format = Uuid)]
    pub id: String,
    /// The service the document belongs to.
    #[schema(example = "billing")]
    pub service: String,
    /// The SHA-256 hash of the document, in lower-case hexadecimal.
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
    /// The number of operations of the document.
    #[schema(minimum = 0)]
    pub operation_count: i64,
    /// What the version changes against the active versions of its service.
    pub diff: RestSpecDiffResponse,
}

impl From<&OpenApiSpecView> for OpenApiSpecResponse {
    fn from(view: &OpenApiSpecView) -> Self {
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
            operation_count: i64::try_from(view.operation_count).unwrap_or(i64::MAX),
            diff: RestSpecDiffResponse::from(&view.diff),
        }
    }
}

#[cfg(test)]
mod tests;
