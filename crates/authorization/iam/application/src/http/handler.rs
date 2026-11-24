//! REST handlers of the IAM context, and the use-case calls that the GraphQL resolvers share.
//!
//! A handler takes the IAM state and the problem-aware extractors only (`ApiPath`,
//! `ValidatedQuery`, `ValidatedJson` and `ApiJson`, and the IAM header extractors
//! `IdempotencyKeyHeader`, `IfMatchHeader` and `PreferWaitHeader`); the test of this module checks every handler
//! against that rule.

use axum::Json;
use axum::extract::State;
use iam_domain::Credential;
use shared_application::http::{Problem, ValidatedJson};

use super::IamState;
use super::dto::{TokenResolutionRequest, TokenResolutionResponse};
use crate::query::resolve_subject_token::ResolveSubjectTokenQuery;

/// Resolves a credential for a validated request; the REST handler and the GraphQL resolver share
/// it.
///
/// # Errors
///
/// The problem of a storage failure; a refused credential is an answer, not an error.
pub(crate) async fn resolve_credential(
    state: &IamState,
    credential: String,
) -> Result<TokenResolutionResponse, Problem> {
    let query = ResolveSubjectTokenQuery {
        credential: Credential::new(credential),
    };
    let resolution = state.query_bus.ask(query).await?;
    Ok(TokenResolutionResponse::from(resolution))
}

/// Resolves a User service token into its subject.
///
/// # Errors
///
/// A problem document: 500 when the revocation state cannot be read.
#[utoipa::path(
    post,
    path = "/token-resolutions",
    operation_id = "api_token_resolutions_post",
    tag = "iam",
    summary = "Resolves a User service token into its subject.",
    description = "Returns the subject, session, roles claim and expiry of a valid, unrevoked token, or `resolved = false` with the token reason code. The credential is never echoed.",
    security(("bearerAuth" = [])),
    request_body(content = TokenResolutionRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "The resolution of the credential.", body = TokenResolutionResponse),
        (status = 400, description = "Invalid input.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 403, description = "The caller may not resolve tokens.", body = Problem, content_type = "application/problem+json"),
        (status = 413, description = "Request body too large.", body = Problem, content_type = "application/problem+json"),
        (status = 415, description = "Unsupported media type.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn resolve(
    State(state): State<IamState>,
    ValidatedJson(body): ValidatedJson<TokenResolutionRequest>,
) -> Result<Json<TokenResolutionResponse>, Problem> {
    Ok(Json(resolve_credential(&state, body.credential).await?))
}

#[cfg(test)]
mod tests;
