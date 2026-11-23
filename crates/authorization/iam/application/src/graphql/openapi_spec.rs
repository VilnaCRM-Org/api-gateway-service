//! GraphQL objects and the resolver of the `OpenAPI` specification operations.
//!
//! The resolver shares the use-case call and the response shapes of the REST handler, so both
//! transports apply one set of rules.

use async_graphql::{Context, ID, InputObject, SimpleObject};
use shared_application::http::Problem;
use validator::Validate as _;

use super::{require_caller, state};
use crate::http::openapi_spec::dto::{
    LoadOpenApiSpecRequest, OpenApiSpecResponse, OperationFlagDowngradeResponse,
    OperationFlagsResponse, OperationWildcardGainResponse, RemovedOperationGrantResponse,
    RestSpecDiffResponse,
};
use crate::http::openapi_spec::load_openapi_spec;

/// Input of the mutation that loads an `OpenAPI` specification.
#[derive(InputObject)]
#[graphql(name = "LoadOpenapiSpecInput")]
pub struct LoadOpenApiSpecInput {
    /// The name of the service the document belongs to: lower-case letters, digits and hyphens, at most 63 characters; `iam` is reserved for IAM's own document.
    pub service: String,
    /// The `OpenAPI` 3.0.x or 3.1.x document as JSON text, at most 5 MiB.
    pub document: String,
}

impl std::fmt::Debug for LoadOpenApiSpecInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadOpenApiSpecInput")
            .field("service", &self.service)
            .finish_non_exhaustive()
    }
}

/// The two flags of an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SimpleObject)]
#[graphql(name = "OperationFlags")]
pub struct OperationFlagsObject {
    /// Whether a wildcard grant never covers the operation (`x-iam-sensitive`).
    pub sensitive: bool,
    /// Whether every use of the operation is audited (`x-iam-audit: always`).
    pub audit_always: bool,
}

impl From<OperationFlagsResponse> for OperationFlagsObject {
    fn from(flags: OperationFlagsResponse) -> Self {
        Self {
            sensitive: flags.sensitive,
            audit_always: flags.audit_always,
        }
    }
}

/// A removed operation that roles grant by its exact key.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "RemovedOperationGrant")]
pub struct RemovedOperationGrantObject {
    /// The removed operation, `{METHOD} {template}`.
    pub operation: String,
    /// The identifiers of the roles that grant it.
    pub roles: Vec<String>,
}

impl From<RemovedOperationGrantResponse> for RemovedOperationGrantObject {
    fn from(grant: RemovedOperationGrantResponse) -> Self {
        Self {
            operation: grant.operation,
            roles: grant.roles,
        }
    }
}

/// A wildcard grant that would cover added operations.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "OperationWildcardGain")]
pub struct OperationWildcardGainObject {
    /// The identifier of the role that holds the grant.
    pub role: String,
    /// The wildcard pattern, such as `rest:billing:GET *`.
    pub pattern: String,
    /// The added operations the pattern would cover.
    pub operations: Vec<String>,
}

impl From<OperationWildcardGainResponse> for OperationWildcardGainObject {
    fn from(gain: OperationWildcardGainResponse) -> Self {
        Self {
            role: gain.role,
            pattern: gain.pattern,
            operations: gain.operations,
        }
    }
}

/// An operation that would lose a flag.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "OperationFlagDowngrade")]
pub struct OperationFlagDowngradeObject {
    /// The operation, `{METHOD} {template}`.
    pub operation: String,
    /// Its flags in the active versions.
    pub before: OperationFlagsObject,
    /// Its flags in the new version.
    pub after: OperationFlagsObject,
}

impl From<OperationFlagDowngradeResponse> for OperationFlagDowngradeObject {
    fn from(downgrade: OperationFlagDowngradeResponse) -> Self {
        Self {
            operation: downgrade.operation,
            before: downgrade.before.into(),
            after: downgrade.after.into(),
        }
    }
}

/// What a version changes against the union of the active versions of its service.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "OpenApiSpecDiff")]
pub struct RestSpecDiffObject {
    /// The operations the version adds.
    pub added: Vec<String>,
    /// The operations the version removes.
    pub removed: Vec<String>,
    /// The removed operations that roles grant by their exact key.
    pub removed_grants: Vec<RemovedOperationGrantObject>,
    /// The wildcard grants that would cover added operations.
    pub wildcard_gains: Vec<OperationWildcardGainObject>,
    /// The operations that would lose a flag.
    pub flag_downgrades: Vec<OperationFlagDowngradeObject>,
}

impl From<RestSpecDiffResponse> for RestSpecDiffObject {
    fn from(diff: RestSpecDiffResponse) -> Self {
        Self {
            added: diff.added,
            removed: diff.removed,
            removed_grants: diff.removed_grants.into_iter().map(Into::into).collect(),
            wildcard_gains: diff.wildcard_gains.into_iter().map(Into::into).collect(),
            flag_downgrades: diff.flag_downgrades.into_iter().map(Into::into).collect(),
        }
    }
}

/// An `OpenAPI` specification version with its diff.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "OpenApiSpec")]
pub struct OpenApiSpecObject {
    /// The identifier of the version.
    pub id: ID,
    /// The service the document belongs to.
    pub service: String,
    /// The SHA-256 hash of the document, in lower-case hexadecimal.
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
    /// The number of operations of the document.
    pub operation_count: i64,
    /// What the version changes against the active versions of its service.
    pub diff: RestSpecDiffObject,
}

impl From<OpenApiSpecResponse> for OpenApiSpecObject {
    fn from(spec: OpenApiSpecResponse) -> Self {
        Self {
            id: ID::from(spec.id),
            service: spec.service,
            content_hash: spec.content_hash,
            status: spec.status,
            uploaded_by: spec.uploaded_by,
            created_at: spec.created_at,
            activated_at: spec.activated_at,
            retired_at: spec.retired_at,
            operation_count: spec.operation_count,
            diff: RestSpecDiffObject::from(spec.diff),
        }
    }
}

/// Loads an `OpenAPI` specification as a draft version, or returns the version that already holds
/// the same document.
pub(super) async fn load_openapi_spec_field(
    ctx: &Context<'_>,
    input: LoadOpenApiSpecInput,
) -> Result<OpenApiSpecObject, Problem> {
    let caller = require_caller(ctx)?;
    let request = LoadOpenApiSpecRequest {
        service: input.service,
        document: input.document,
    };
    request.validate()?;
    let loaded = load_openapi_spec(state(ctx)?, caller, request).await?;
    Ok(OpenApiSpecObject::from(OpenApiSpecResponse::from(
        &loaded.view,
    )))
}

#[cfg(test)]
mod tests;
