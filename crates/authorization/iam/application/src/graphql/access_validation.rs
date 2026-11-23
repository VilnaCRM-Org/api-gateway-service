//! GraphQL objects and the resolver of the access-validation query.
//!
//! The resolver shares the use-case call and the response shape of the REST handler, so both
//! transports apply one set of rules.

use async_graphql::{Context, ID, InputObject, SimpleObject};
use shared_application::http::Problem;
use validator::Validate as _;

use super::{require_caller, state};
use crate::http::access_validation::batch::ValidateAccessBatchRequest;
use crate::http::access_validation::dto::{
    AccessSubjectDto, AccessValidationResponse, GraphQlTargetDto, RestTargetDto, ScopesResponse,
    ValidateAccessRequest,
};
use crate::http::access_validation::{validate_access, validate_access_batch};

/// The REST request that a check names.
#[derive(Debug, InputObject)]
#[graphql(name = "AccessRestTargetInput")]
pub struct AccessRestTargetInput {
    /// The HTTP method, in upper case: `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE` or `OPTIONS`.
    pub method: String,
    /// The path of the request as received; IAM normalises it and matches it against the operation templates of the active `OpenAPI` versions of the service.
    pub path: String,
}

/// The GraphQL document that a check names.
#[derive(Debug, InputObject)]
#[graphql(name = "AccessGraphQlTargetInput")]
pub struct AccessGraphQlTargetInput {
    /// The document as the caller received it; IAM resolves every field it selects against the active GraphQL versions of the service. A document over a limit is decided as a deny with `limits_exceeded`.
    pub document: String,
    /// The operation to check; optional when the document holds exactly one operation.
    pub operation_name: Option<String>,
}

/// Input of the access-validation query.
// Its `Debug` output never shows the credential.
#[derive(InputObject)]
#[graphql(name = "ValidateAccessInput")]
pub struct ValidateAccessInput {
    /// The subject's access token as the caller received it; an empty one is decided as `token_missing`.
    pub credential: String,
    /// The target service, as registered in IAM.
    pub service: String,
    /// A REST request to check; exactly one of `rest`, `graphql` and `permissions` is given.
    pub rest: Option<AccessRestTargetInput>,
    /// A GraphQL document to check; exactly one of `rest`, `graphql` and `permissions` is given. The decision is all-or-nothing and `denied` lists every coordinate the subject does not hold.
    pub graphql: Option<AccessGraphQlTargetInput>,
    /// The permission keys to check, 1 to 100; exactly one of `rest`, `graphql` and `permissions` is given.
    pub permissions: Option<Vec<String>>,
    /// The project in which the check is made; without it, project assignments contribute their projects to `scopes`.
    pub project_id: Option<String>,
    /// The policy version that the decision must reflect at least; a version that IAM has not issued yet fails with `VALIDATION_FAILED`.
    pub min_policy_version: Option<i64>,
    /// An opaque identifier of the caller's request, 1 to 128 visible ASCII characters; the response echoes it.
    pub request_id: String,
}

impl std::fmt::Debug for ValidateAccessInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidateAccessInput")
            .finish_non_exhaustive()
    }
}

impl From<ValidateAccessInput> for ValidateAccessRequest {
    fn from(input: ValidateAccessInput) -> Self {
        Self {
            credential: input.credential,
            service: input.service,
            rest: input.rest.map(|rest| RestTargetDto {
                method: rest.method,
                path: rest.path,
            }),
            graphql: input.graphql.map(|graphql| GraphQlTargetDto {
                document: graphql.document,
                operation_name: graphql.operation_name,
            }),
            permissions: input.permissions,
            project_id: input.project_id,
            min_policy_version: input.min_policy_version,
            request_id: input.request_id,
        }
    }
}

/// The projects in which an allow holds.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "AccessScopes")]
pub struct AccessScopesObject {
    /// Whether a global assignment holds every required key, so that the allow holds in every project.
    pub all: bool,
    /// The projects that hold every required key when `all` is false; empty for a deny and for `all`.
    pub projects: Vec<String>,
}

impl From<ScopesResponse> for AccessScopesObject {
    fn from(scopes: ScopesResponse) -> Self {
        match scopes {
            ScopesResponse::All(_marker) => Self {
                all: true,
                projects: Vec::new(),
            },
            ScopesResponse::Projects(projects) => Self {
                all: false,
                projects,
            },
        }
    }
}

/// The subject that a decision was made for.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "AccessSubject")]
pub struct AccessSubjectObject {
    /// The user id, or the service name of a service principal.
    pub id: String,
    /// `user` or `service`.
    pub kind: String,
}

impl From<AccessSubjectDto> for AccessSubjectObject {
    fn from(subject: AccessSubjectDto) -> Self {
        Self {
            id: subject.id,
            kind: subject.kind,
        }
    }
}

/// The decision of an access check.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "AccessValidation")]
pub struct AccessValidationObject {
    /// `allow` or `deny`.
    pub decision: String,
    /// `allowed`, `token_missing`, `token_invalid`, `token_expired`, `token_revoked`, `unknown_service`, `unknown_operation`, `malformed_operation`, `permission_missing`, `scope_missing`, `limits_exceeded` or `unavailable`.
    pub reason: String,
    /// The keys or coordinates that are denied; empty for an allow.
    pub denied: Vec<String>,
    /// The projects in which an allow holds; empty for a deny.
    pub scopes: AccessScopesObject,
    /// The subject of the token; null when no token resolved.
    pub subject: Option<AccessSubjectObject>,
    /// The identifier of this decision.
    pub decision_id: ID,
    /// The policy version that the decision reflects; null when no policy was read.
    pub policy_version: Option<i64>,
    /// The request id of the caller, as sent.
    pub request_id: String,
}

impl From<AccessValidationResponse> for AccessValidationObject {
    fn from(response: AccessValidationResponse) -> Self {
        Self {
            decision: response.decision,
            reason: response.reason,
            denied: response.denied,
            scopes: response.scopes.into(),
            subject: response.subject.map(AccessSubjectObject::from),
            decision_id: ID::from(response.decision_id),
            policy_version: response.policy_version,
            request_id: response.request_id,
        }
    }
}

/// Decides one check.
pub(super) async fn validate_access_field(
    ctx: &Context<'_>,
    input: ValidateAccessInput,
) -> Result<AccessValidationObject, Problem> {
    require_caller(ctx)?;
    let request = ValidateAccessRequest::from(input);
    request.validate()?;
    let response = validate_access(state(ctx)?, request).await?;
    Ok(AccessValidationObject::from(response))
}

/// Decides a batch of checks, one decision per input in the order of the inputs.
pub(super) async fn validate_access_batch_field(
    ctx: &Context<'_>,
    inputs: Vec<ValidateAccessInput>,
) -> Result<Vec<AccessValidationObject>, Problem> {
    require_caller(ctx)?;
    let request = ValidateAccessBatchRequest {
        checks: inputs
            .into_iter()
            .map(ValidateAccessRequest::from)
            .collect(),
    };
    request.validate()?;
    let response = validate_access_batch(state(ctx)?, request).await?;
    Ok(response
        .results
        .into_iter()
        .map(AccessValidationObject::from)
        .collect())
}

#[cfg(test)]
mod tests;
