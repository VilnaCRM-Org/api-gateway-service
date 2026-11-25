//! The REST handler of the access-validation operation, and the use-case call that the GraphQL
//! resolver shares.
//!
//! A handler takes the IAM state and the problem-aware extractors only (`ValidatedJson` and the
//! IAM extractor `CallerPrincipal`); the test of the `handler` module checks every handler
//! against that rule.

pub mod batch;
pub mod dto;

use axum::Json;
use axum::extract::State;
use shared_application::http::{Problem, ValidatedJson};

use super::IamState;
use super::extract::CallerPrincipal;
use crate::gateway_decision::stale::{ValidateAccessStaleBatchQuery, ValidateAccessStaleQuery};
use batch::{AccessValidationBatchResponse, ValidateAccessBatchRequest};
use dto::{AccessValidationResponse, ValidateAccessRequest};

/// The largest body of a batch: room for 100 checks, each as large as the 64 KiB that the
/// composition root allows a single check by default, above the limit of the other routes.
pub const ACCESS_VALIDATION_BATCH_BODY_LIMIT_BYTES: usize = 100 * 64 * 1024;

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

/// Decides a validated batch; the REST handler and the GraphQL resolver share it.
///
/// Every item is decided on its own and in request order: an item that cannot be read is a deny,
/// never an error.
///
/// # Errors
///
/// The problem of an internal failure of the batch.
pub(crate) async fn validate_access_batch(
    state: &IamState,
    request: ValidateAccessBatchRequest,
) -> Result<AccessValidationBatchResponse, Problem> {
    let parsed = request.parse();
    let outcomes = state.query_bus.ask(parsed.query).await?;
    Ok(AccessValidationBatchResponse::new(
        &outcomes,
        parsed.request_ids,
    ))
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
    description = "Decides one check for the bearer of `credential` on the target `service`: a REST request (`rest`), a GraphQL document (`graphql`) or a list of permission keys (`permissions`), exactly one of them. A GraphQL document is allowed only when the subject holds every coordinate it selects; `denied` lists every coordinate it does not hold, and a document over a limit is a deny with `limits_exceeded`. A valid request always returns 200 with a decision body: `allow`, or `deny` with the `reason` and the `denied` keys or coordinates. A `minPolicyVersion` above the current policy version is refused with 422. The credential is never echoed.",
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

/// Validates access for a batch of checks.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 422 for a batch of no check or of more than 100.
#[utoipa::path(
    post,
    path = "/access-validations/batch",
    operation_id = "api_access_validations_batch_post",
    tag = "iam",
    summary = "Validates a batch of access checks.",
    description = "Decides 1 to 100 checks of the shape of `POST /access-validations` and returns one result per check, in the order of the request, each with its own `decisionId`. The checks are decided independently: a check that cannot be read produces a `deny` result with the reason `malformed_operation` and does not fail the others, and each distinct credential is resolved once per batch. A batch of no check or of more than 100 is refused with 422. The credentials are never echoed.",
    security(("bearerAuth" = [])),
    request_body(content = ValidateAccessBatchRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "The decisions, in request order.", body = AccessValidationBatchResponse),
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
pub async fn validate_batch(
    State(state): State<IamState>,
    CallerPrincipal(_caller): CallerPrincipal,
    ValidatedJson(body): ValidatedJson<ValidateAccessBatchRequest>,
) -> Result<Json<AccessValidationBatchResponse>, Problem> {
    Ok(Json(validate_access_batch(&state, body).await?))
}

/// Answers a check without authenticating its caller.
///
/// The gateway's decision listener routes the access validations here while its snapshot is not
/// proven fresh: the caller rule cannot be read then, and the decision API always answers with a
/// decision body. The handler validates the body and asks the bus for the stale answer only, the
/// deny `unavailable`, which the stale handler also writes to the access log; it never asks for a
/// real decision, so a snapshot that turns fresh in between cannot give an unauthenticated caller
/// one.
///
/// # Errors
///
/// A problem document: 422 for an invalid request.
pub async fn validate_unauthenticated(
    State(state): State<IamState>,
    ValidatedJson(body): ValidatedJson<ValidateAccessRequest>,
) -> Result<Json<AccessValidationResponse>, Problem> {
    let parsed = body.parse()?;
    let outcome = state
        .query_bus
        .ask(ValidateAccessStaleQuery(parsed.query))
        .await?;
    Ok(Json(AccessValidationResponse::new(
        &outcome,
        &parsed.request_id,
    )))
}

/// Answers a batch of checks without authenticating its caller; see [`validate_unauthenticated`].
///
/// Every readable item is the deny `unavailable` and every unreadable one `malformed_operation`,
/// each with its own decision id and its own access record, in request order.
///
/// # Errors
///
/// A problem document: 422 for a batch of no check or of more than 100.
pub async fn validate_batch_unauthenticated(
    State(state): State<IamState>,
    ValidatedJson(body): ValidatedJson<ValidateAccessBatchRequest>,
) -> Result<Json<AccessValidationBatchResponse>, Problem> {
    let parsed = body.parse();
    let outcomes = state
        .query_bus
        .ask(ValidateAccessStaleBatchQuery(parsed.query))
        .await?;
    Ok(Json(AccessValidationBatchResponse::new(
        &outcomes,
        parsed.request_ids,
    )))
}

#[cfg(test)]
mod tests;
