//! REST handlers that read session revocations and token cut-offs, and the use-case calls that
//! the GraphQL resolvers share (FR-81).
//!
//! A handler takes the IAM state and the problem-aware extractors only (`ApiPath`,
//! `ValidatedQuery`, the IAM extractor `CallerPrincipal`); the test of the `handler` module checks
//! every handler against that rule. The operations need `iam:audit:read`, which the access guard
//! enforces from its rule table.

pub mod dto;

use axum::Json;
use axum::extract::State;
use iam_domain::{GlobalTokenCutoff, SessionRevocation, SessionRevocationId};
use shared_application::http::{ApiPath, Problem, ValidatedQuery, Violation};
use shared_domain::Uuid;

use super::IamState;
use super::extract::CallerPrincipal;
use crate::error::IamError;
use crate::query::get_global_token_cutoff::GetGlobalTokenCutoffQuery;
use crate::query::get_session_revocation::GetSessionRevocationQuery;
use crate::query::get_user_token_cutoff::{GetUserTokenCutoffQuery, UserTokenCutoffView};
use crate::query::list_session_revocations::SessionRevocationPage;
use dto::{
    GlobalTokenCutoffResponse, ListSessionRevocationsParams, SessionRevocationPageResponse,
    SessionRevocationResponse, UserTokenCutoffResponse, parse_user,
};

/// The session revocation id of a path or an argument.
///
/// # Errors
///
/// [`IamError::Invalid`] with a violation of `id` when the text is not a UUID.
pub(crate) fn parse_session_revocation_id(text: &str) -> Result<SessionRevocationId, IamError> {
    SessionRevocationId::parse(text).map_err(|_error| {
        IamError::Invalid(vec![Violation {
            property_path: "id".to_owned(),
            message: "This value is not a valid UUID.".to_owned(),
            code: "uuid".to_owned(),
        }])
    })
}

/// The session revocation with the identifier, none when it is unknown.
///
/// # Errors
///
/// The 500 problem of a storage failure.
pub(crate) async fn find_session_revocation(
    state: &IamState,
    id: SessionRevocationId,
) -> Result<Option<SessionRevocation>, Problem> {
    Ok(state
        .query_bus
        .ask(GetSessionRevocationQuery { id })
        .await?)
}

/// One page of session revocations for validated parameters.
///
/// # Errors
///
/// The 422 problem of an invalid parameter, the 500 problem of a storage failure.
pub(crate) async fn list_session_revocations(
    state: &IamState,
    params: ListSessionRevocationsParams,
) -> Result<SessionRevocationPage, Problem> {
    Ok(state.query_bus.ask(params.into_query()?).await?)
}

/// The cut-off of the tokens of `user`, none when the user has none.
///
/// # Errors
///
/// The 500 problem of a storage failure.
pub(crate) async fn find_user_token_cutoff(
    state: &IamState,
    user: Uuid,
) -> Result<Option<UserTokenCutoffView>, Problem> {
    Ok(state
        .query_bus
        .ask(GetUserTokenCutoffQuery { user })
        .await?)
}

/// The global token cut-off, none when it was never set.
///
/// # Errors
///
/// The 500 problem of a storage failure.
pub(crate) async fn find_global_token_cutoff(
    state: &IamState,
) -> Result<Option<GlobalTokenCutoff>, Problem> {
    Ok(state.query_bus.ask(GetGlobalTokenCutoffQuery).await?)
}

/// Lists session revocations.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without `iam:audit:read`, 422 for an invalid
/// parameter.
#[utoipa::path(
    get,
    path = "/session-revocations",
    operation_id = "api_session_revocations_get",
    tag = "iam",
    summary = "Retrieves the collection of session revocations.",
    description = "Returns one page of session revocations, newest first, each with its session, user, source (`user-service` or `operator`), actor and time. The filters `userId`, `source` and the time range `from` (inclusive) and `until` (exclusive) keep the revocations that meet every one given. `nextCursor` goes into `after` for the next, older page. The caller needs `iam:audit:read`.",
    security(("bearerAuth" = [])),
    params(ListSessionRevocationsParams),
    responses(
        (status = 200, description = "One page of session revocations.", body = SessionRevocationPageResponse),
        (status = 400, description = "Invalid query parameter.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 403, description = "The caller lacks `iam:audit:read`.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn list(
    State(state): State<IamState>,
    CallerPrincipal(_caller): CallerPrincipal,
    ValidatedQuery(params): ValidatedQuery<ListSessionRevocationsParams>,
) -> Result<Json<SessionRevocationPageResponse>, Problem> {
    let page = list_session_revocations(&state, params).await?;
    Ok(Json(SessionRevocationPageResponse::from(&page)))
}

/// Reads one session revocation.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without `iam:audit:read`, 404 for an unknown
/// revocation, 422 for an id that is not a UUID.
#[utoipa::path(
    get,
    path = "/session-revocations/{id}",
    operation_id = "api_session_revocations_id_get",
    tag = "iam",
    summary = "Retrieves a session revocation.",
    description = "Returns the session revocation with the identifier: its session, user, source (`user-service` or `operator`), actor and time. The caller needs `iam:audit:read`.",
    security(("bearerAuth" = [])),
    params(("id" = String, Path, format = Uuid, description = "Session revocation identifier")),
    responses(
        (status = 200, description = "The session revocation.", body = SessionRevocationResponse),
        (status = 400, description = "Invalid identifier.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 403, description = "The caller lacks `iam:audit:read`.", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Session revocation not found.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn get_one(
    State(state): State<IamState>,
    CallerPrincipal(_caller): CallerPrincipal,
    ApiPath(id): ApiPath<String>,
) -> Result<Json<SessionRevocationResponse>, Problem> {
    let revocation = find_session_revocation(&state, parse_session_revocation_id(&id)?)
        .await?
        .ok_or(IamError::NotFound)?;
    Ok(Json(SessionRevocationResponse::from(&revocation)))
}

/// Reads the token cut-off of one user.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without `iam:audit:read`, 404 for a user
/// without a cut-off, 422 for a user id that is not a UUID.
#[utoipa::path(
    get,
    path = "/users/{userId}/token-cutoff",
    operation_id = "api_users_user_id_token_cutoff_get",
    tag = "iam",
    summary = "Retrieves the token cut-off of a user.",
    description = "Returns the instant at or before which the tokens of the user are refused, with the source (`user-service` or `operator`) and the actor of the cut-off. A user without a cut-off is a 404. The caller needs `iam:audit:read`.",
    security(("bearerAuth" = [])),
    params(("userId" = String, Path, format = Uuid, description = "User identifier")),
    responses(
        (status = 200, description = "The token cut-off of the user.", body = UserTokenCutoffResponse),
        (status = 400, description = "Invalid identifier.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 403, description = "The caller lacks `iam:audit:read`.", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "The user has no token cut-off.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn user_cutoff(
    State(state): State<IamState>,
    CallerPrincipal(_caller): CallerPrincipal,
    ApiPath(user_id): ApiPath<String>,
) -> Result<Json<UserTokenCutoffResponse>, Problem> {
    let view = find_user_token_cutoff(&state, parse_user("userId", &user_id)?)
        .await?
        .ok_or(IamError::NotFound)?;
    Ok(Json(UserTokenCutoffResponse::from(&view)))
}

/// Reads the global token cut-off.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without `iam:audit:read`, 404 when the
/// global cut-off was never set.
#[utoipa::path(
    get,
    path = "/global-token-cutoffs/current",
    operation_id = "api_global_token_cutoffs_current_get",
    tag = "iam",
    summary = "Retrieves the current global token cut-off.",
    description = "Returns the instant at or before which every token is refused, with the source and the actor that set it. A 404 means that the global cut-off was never set. The caller needs `iam:audit:read`.",
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "The global token cut-off.", body = GlobalTokenCutoffResponse),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 403, description = "The caller lacks `iam:audit:read`.", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "The global token cut-off was never set.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn global_cutoff(
    State(state): State<IamState>,
    CallerPrincipal(_caller): CallerPrincipal,
) -> Result<Json<GlobalTokenCutoffResponse>, Problem> {
    let cutoff = find_global_token_cutoff(&state)
        .await?
        .ok_or(IamError::NotFound)?;
    Ok(Json(GlobalTokenCutoffResponse::from(&cutoff)))
}

#[cfg(test)]
mod tests;
