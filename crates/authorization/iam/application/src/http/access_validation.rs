//! The REST handler of the access-validation operation, and the use-case call that the GraphQL
//! resolver shares.
//!
//! A handler takes the IAM state and the problem-aware extractors only (`ValidatedJson` and the
//! IAM extractor `CallerPrincipal`); the test of the `handler` module checks every handler
//! against that rule.

pub mod dto;

use axum::Json;
use axum::extract::State;
use shared_application::http::{Problem, ValidatedJson};

use super::IamState;
use super::extract::CallerPrincipal;
use dto::{AccessValidationResponse, ValidateAccessRequest};

/// Decides a validated request; the REST handler and the GraphQL resolver share it.
///
/// # Errors
///
/// The 422 problem of a request that names no target or two, or a value that breaks its rule, or
/// a policy version that IAM has not issued; a denied check is an answer, not an error.
pub(crate) async fn validate_access(
    state: &IamState,
    request: ValidateAccessRequest,
) -> Result<AccessValidationResponse, Problem> {
    let parsed = request.parse()?;
    let outcome = state.query_bus.ask(parsed.query).await?;
    Ok(AccessValidationResponse::new(&outcome, &parsed.request_id))
}

/// Validates access.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 422 for an invalid request.
#[utoipa::path(
    post,
    path = "/access-validations",
    operation_id = "api_access_validations_post",
    tag = "iam",
    summary = "Validates whether a subject may perform an operation or hold permission keys.",
    description = "Decides one check for the bearer of `credential` on the target `service`: a REST request (`rest`) or a list of permission keys (`permissions`), exactly one of them. A valid request always returns 200 with a decision body: `allow`, or `deny` with the `reason` and the `denied` keys. A `minPolicyVersion` above the current policy version is refused with 422. The credential is never echoed.",
    security(("bearerAuth" = [])),
    request_body(content = ValidateAccessRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "The decision.", body = AccessValidationResponse),
        (status = 400, description = "Invalid input.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 403, description = "The caller may not validate access.", body = Problem, content_type = "application/problem+json"),
        (status = 413, description = "Request body too large.", body = Problem, content_type = "application/problem+json"),
        (status = 415, description = "Unsupported media type.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn validate(
    State(state): State<IamState>,
    CallerPrincipal(_caller): CallerPrincipal,
    ValidatedJson(body): ValidatedJson<ValidateAccessRequest>,
) -> Result<Json<AccessValidationResponse>, Problem> {
    Ok(Json(validate_access(&state, body).await?))
}

#[cfg(test)]
mod tests;
