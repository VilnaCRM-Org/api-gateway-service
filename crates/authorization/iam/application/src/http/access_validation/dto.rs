//! Wire shapes of the access-validation operation of the IAM context.
//!
//! Each one keeps its schema constraints and its validator attributes on the same field so that
//! both stay equal.

use iam_domain::{
    AccessCheck, AccessTarget, Credential, DecisionOutcome, GraphQlTarget, HttpMethod,
    InvalidIamValue, PermissionsTarget, PolicyVersion, ProjectId, RequestId, RestTarget, ScopeSet,
    ServiceName, SubjectRef,
};
use serde::{Deserialize, Serialize};
use shared_application::http::Violation;
use utoipa::ToSchema;
use validator::Validate;

use crate::error::IamError;
use crate::query::validate_access::ValidateAccessQuery;

/// The REST request that a check names.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, ToSchema, Validate)]
#[serde(deny_unknown_fields)]
#[schema(as = AccessValidationRestTarget)]
pub struct RestTargetDto {
    /// The HTTP method, in upper case: `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE` or
    /// `OPTIONS`.
    #[schema(example = "GET")]
    #[validate(length(
        min = 1,
        max = 16,
        message = "This value must contain between 1 and 16 characters."
    ))]
    pub method: String,
    /// The path of the request as received; IAM normalises it and matches it against the
    /// operation templates of the active `OpenAPI` versions of the service.
    #[schema(example = "/api/invoices/42")]
    pub path: String,
}

/// The GraphQL document that a check names.
///
/// A document over a limit of the decision API is not refused here: it is decided as a deny with
/// `limits_exceeded`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(as = AccessValidationGraphQlTarget)]
pub struct GraphQlTargetDto {
    /// The document as the caller received it; IAM resolves every field it selects against the
    /// active GraphQL versions of the service.
    #[schema(example = "{ invoice(id: 42) { id total } }")]
    pub document: String,
    /// The operation to check; optional when the document holds exactly one operation.
    #[serde(default)]
    #[schema(max_length = 256, example = "GetInvoice")]
    #[validate(length(max = 256, message = "This value must contain at most 256 characters."))]
    pub operation_name: Option<String>,
}

/// Body of the access-validation operation: who asks, about which service, and what is checked.
///
/// Its `Debug` output never shows the credential.
#[derive(Clone, Deserialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(as = ValidateAccessRequest)]
pub struct ValidateAccessRequest {
    /// The subject's access token as the caller received it; an empty one is decided as
    /// `token_missing`.
    #[schema(max_length = 8192, example = "eyJhbGciOiJSUzI1NiJ9.e30.c2lnbmF0dXJl")]
    #[validate(length(
        max = 8192,
        message = "This value must contain at most 8192 characters."
    ))]
    pub credential: String,
    /// The target service, as registered in IAM.
    #[schema(min_length = 1, max_length = 63, example = "billing")]
    #[validate(length(
        min = 1,
        max = 63,
        message = "This value must contain between 1 and 63 characters."
    ))]
    pub service: String,
    /// A REST request to check; exactly one of `rest`, `graphql` and `permissions` is given.
    #[serde(default)]
    #[validate(nested)]
    pub rest: Option<RestTargetDto>,
    /// A GraphQL document to check; exactly one of `rest`, `graphql` and `permissions` is given.
    /// The decision is all-or-nothing: the document is allowed only when the subject holds the key
    /// of every coordinate it selects, and `denied` lists every coordinate it does not hold.
    #[serde(default)]
    #[validate(nested)]
    pub graphql: Option<GraphQlTargetDto>,
    /// The permission keys to check, 1 to 100; exactly one of `rest`, `graphql` and
    /// `permissions` is given.
    #[serde(default)]
    #[schema(min_items = 1, max_items = 100)]
    #[validate(length(
        min = 1,
        max = 100,
        message = "This collection must contain between 1 and 100 elements."
    ))]
    pub permissions: Option<Vec<String>>,
    /// The project in which the check is made; without it, project assignments contribute their
    /// projects to `scopes`.
    #[serde(default)]
    #[schema(format = Uuid)]
    #[validate(length(max = 64, message = "This value must contain 64 characters or fewer."))]
    pub project_id: Option<String>,
    /// The policy version that the decision must reflect at least; a version that IAM has not
    /// issued yet is refused with 422.
    #[serde(default)]
    #[schema(minimum = 0)]
    pub min_policy_version: Option<i64>,
    /// An opaque identifier of the caller's request, 1 to 128 visible ASCII characters; the
    /// response echoes it.
    #[schema(min_length = 1, max_length = 128, example = "req-0190f2a8")]
    #[validate(length(
        min = 1,
        max = 128,
        message = "This value must contain between 1 and 128 characters."
    ))]
    pub request_id: String,
}

impl std::fmt::Debug for ValidateAccessRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidateAccessRequest")
            .finish_non_exhaustive()
    }
}

/// A request once parsed: the query to ask and the request id to echo.
#[derive(Debug, Clone)]
pub struct ParsedValidation {
    /// The question for the decision path.
    pub query: ValidateAccessQuery,
    /// The request id of the caller.
    pub request_id: RequestId,
}

impl ValidateAccessRequest {
    /// Parses the service, the one target, the project, the policy version and the request id.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with every violation, in the order service, target, project,
    /// policy version, request id.
    pub fn parse(self) -> Result<ParsedValidation, IamError> {
        let service = ServiceName::new(&self.service).map_err(|error| violation_of(error, None));
        let target = parse_target(self.rest.as_ref(), self.graphql, self.permissions);
        let project = self
            .project_id
            .as_deref()
            .map(ProjectId::parse)
            .transpose()
            .map_err(|error| violation_of(error, Some("projectId")));
        let minimum = self
            .min_policy_version
            .map(PolicyVersion::new)
            .transpose()
            .map_err(|error| violation_of(error, Some("minPolicyVersion")));
        let request_id =
            RequestId::new(&self.request_id).map_err(|error| violation_of(error, None));
        match (service, target, project, minimum, request_id) {
            (Ok(service), Ok(target), Ok(project), Ok(minimum), Ok(request_id)) => {
                Ok(ParsedValidation {
                    query: ValidateAccessQuery {
                        credential: Credential::new(self.credential),
                        check: AccessCheck::new(service, target, project, minimum),
                    },
                    request_id,
                })
            }
            (service, target, project, minimum, request_id) => Err(IamError::Invalid(
                service
                    .err()
                    .into_iter()
                    .chain(target.err())
                    .chain(project.err())
                    .chain(minimum.err())
                    .chain(request_id.err())
                    .collect(),
            )),
        }
    }
}

/// The one target of a request: a request with none or with several is a violation of `target`.
fn parse_target(
    rest: Option<&RestTargetDto>,
    graphql: Option<GraphQlTargetDto>,
    permissions: Option<Vec<String>>,
) -> Result<AccessTarget, Violation> {
    match (rest, graphql, permissions) {
        (Some(rest), None, None) => HttpMethod::parse(&rest.method)
            .map(|method| AccessTarget::Rest(RestTarget::new(method, rest.path.clone())))
            .ok_or_else(|| Violation {
                property_path: "rest.method".to_owned(),
                message:
                    "This value must be one of GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS."
                        .to_owned(),
                code: "choice".to_owned(),
            }),
        (None, Some(graphql), None) => Ok(AccessTarget::GraphQl(GraphQlTarget::new(
            graphql.document,
            graphql.operation_name,
        ))),
        (None, None, Some(keys)) => PermissionsTarget::new(keys)
            .map(AccessTarget::Permissions)
            .map_err(|error| Violation {
                property_path: error.property_path().to_owned(),
                message: error.to_string(),
                code: error.code().to_owned(),
            }),
        _ => Err(Violation {
            property_path: "target".to_owned(),
            message: "Exactly one of rest, graphql and permissions must be given.".to_owned(),
            code: "choice".to_owned(),
        }),
    }
}

/// The violation that `error` describes, at `property_path` or at the path of the error.
fn violation_of(error: InvalidIamValue, property_path: Option<&str>) -> Violation {
    Violation {
        property_path: property_path
            .unwrap_or_else(|| error.property_path())
            .to_owned(),
        message: error.to_string(),
        code: error.code().to_owned(),
    }
}

/// The subject that a decision was made for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = AccessSubject)]
pub struct AccessSubjectDto {
    /// The user id, or the service name of a service principal.
    pub id: String,
    /// `user` or `service`.
    #[schema(example = "user")]
    pub kind: String,
}

impl From<&SubjectRef> for AccessSubjectDto {
    fn from(subject: &SubjectRef) -> Self {
        Self {
            id: subject.id().to_string(),
            kind: subject.kind().as_str().to_owned(),
        }
    }
}

/// The marker of a decision that holds in every project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
#[schema(as = AllProjects)]
pub enum AllProjects {
    /// Every project.
    All,
}

/// The projects in which an allow holds: `all`, or the project ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(untagged)]
#[schema(as = AccessScopes)]
pub enum ScopesResponse {
    /// A global assignment holds every required key.
    All(AllProjects),
    /// Only these projects hold every required key; empty for a deny.
    Projects(Vec<String>),
}

impl From<&ScopeSet> for ScopesResponse {
    fn from(scopes: &ScopeSet) -> Self {
        match scopes {
            ScopeSet::All => Self::All(AllProjects::All),
            ScopeSet::Projects(projects) => {
                Self::Projects(projects.iter().map(ToString::to_string).collect())
            }
        }
    }
}

/// The decision body of the access-validation operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = AccessValidation)]
pub struct AccessValidationResponse {
    /// `allow` or `deny`.
    #[schema(example = "deny")]
    pub decision: String,
    /// `allowed`, `token_missing`, `token_invalid`, `token_expired`, `token_revoked`,
    /// `unknown_service`, `unknown_operation`, `malformed_operation`, `permission_missing`,
    /// `scope_missing`, `limits_exceeded` or `unavailable`.
    #[schema(example = "permission_missing")]
    pub reason: String,
    /// The keys or coordinates that are denied; empty for an allow.
    pub denied: Vec<String>,
    /// The projects in which an allow holds: `all` or a list of project ids; empty for a deny.
    pub scopes: ScopesResponse,
    /// The subject of the token; absent when no token resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<AccessSubjectDto>,
    /// The identifier of this decision.
    #[schema(format = Uuid)]
    pub decision_id: String,
    /// The policy version that the decision reflects; absent when no policy was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(minimum = 0)]
    pub policy_version: Option<i64>,
    /// The request id of the caller, as sent.
    pub request_id: String,
}

impl AccessValidationResponse {
    /// The body for `outcome` and the request id of the check.
    #[must_use]
    pub fn new(outcome: &DecisionOutcome, request_id: &RequestId) -> Self {
        Self::echoing(outcome, request_id.to_string())
    }

    /// The body for `outcome` that echoes `request_id` as the caller sent it, which a batch does
    /// for an item that did not parse.
    #[must_use]
    pub fn echoing(outcome: &DecisionOutcome, request_id: String) -> Self {
        Self {
            decision: outcome.decision().as_str().to_owned(),
            reason: outcome.reason().as_str().to_owned(),
            denied: outcome.denied().to_vec(),
            scopes: ScopesResponse::from(outcome.scopes()),
            subject: outcome.subject().map(AccessSubjectDto::from),
            decision_id: outcome.decision_id().to_string(),
            policy_version: outcome.policy_version().map(PolicyVersion::value),
            request_id,
        }
    }
}

#[cfg(test)]
mod tests;
