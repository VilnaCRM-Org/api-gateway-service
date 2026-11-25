//! REST handlers that read the access decisions of the gateway from the log store, and the
//! use-case calls that the GraphQL resolvers share.
//!
//! A handler takes the IAM state and the problem-aware extractors only (`ApiPath`,
//! `ValidatedQuery`, the IAM extractor `CallerPrincipal`); the test of the `handler` module checks
//! every handler against that rule. Every successful read is recorded in the audit log by the use
//! case.

pub mod dto;

use axum::Json;
use axum::extract::State;
use iam_domain::AccessLogEntry;
use shared_application::http::{ApiPath, Problem, ValidatedQuery, Violation};
use shared_domain::Uuid;

use super::IamState;
use super::extract::CallerPrincipal;
use crate::error::IamError;
use crate::principal::Principal;
use crate::query::get_access_decision::GetAccessDecisionQuery;
use crate::query::get_access_decisions::AccessDecisionPage;
use dto::{AccessDecisionPageResponse, AccessDecisionResponse, ListAccessDecisionsParams};

/// The decision id of a path or an argument.
///
/// # Errors
///
/// [`IamError::Invalid`] with a violation of `id` when the text is not a UUID.
pub(crate) fn parse_access_decision_id(text: &str) -> Result<Uuid, IamError> {
    Uuid::parse(text).map_err(|_error| {
        IamError::Invalid(vec![Violation {
            property_path: "id".to_owned(),
            message: "This value is not a valid UUID.".to_owned(),
            code: "uuid".to_owned(),
        }])
    })
}

/// The decision with the identifier, read as `caller`; none when the log store holds none.
///
/// # Errors
///
/// The 503 or 504 problem of a log store that fails, the 500 problem of a read that cannot be
/// audited.
pub(crate) async fn find_access_decision(
    state: &IamState,
    caller: &Principal,
    id: Uuid,
) -> Result<Option<AccessLogEntry>, Problem> {
    let query = GetAccessDecisionQuery {
        actor: caller.actor(),
        id,
    };
    Ok(state.query_bus.ask(query).await?)
}

/// One page of decisions for validated parameters, read as `caller`.
///
/// # Errors
///
/// The 422 problem of an invalid parameter or range, the 503 or 504 problem of a log store that
/// fails, the 500 problem of a search that cannot be audited.
pub(crate) async fn list_access_decisions(
    state: &IamState,
    caller: &Principal,
    params: ListAccessDecisionsParams,
) -> Result<AccessDecisionPage, Problem> {
    let query = params.into_query(caller.actor())?;
    Ok(state.query_bus.ask(query).await?)
}

/// Searches the access decisions.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without `iam:audit:read`, 422 for an invalid
/// parameter or a missing or too long range, 503 when the log store is unavailable, 504 when it
/// does not answer in time.
#[utoipa::path(
    get,
    path = "/access-decisions",
    operation_id = "api_access_decisions_get",
    tag = "iam",
    summary = "Searches the access decisions of the gateway.",
    description = "Returns one page of the access decisions that the gateway logged in the audit lane, newest first, in the time range `from` to `until`, which is required and may span at most `ACCESS_LOG_QUERY_MAX_RANGE`. Every filter given must match: subject id, subject kind, decision, reason, upstream, route id and status. A page holds at most 500 decisions; `nextCursor` goes into `after` for the next, older page, and every decision is returned exactly once, including decisions that share a timestamp. A query that exceeds `ACCESS_LOG_QUERY_TIMEOUT` returns 504 and no partial page; a log store that cannot be reached returns 503. The caller needs `iam:audit:read`, and the search is itself recorded in the security audit log as `access_log.list`.",
    security(("bearerAuth" = [])),
    params(ListAccessDecisionsParams),
    responses(
        (status = 200, description = "One page of access decisions.", body = AccessDecisionPageResponse),
        (status = 400, description = "Invalid query parameter.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 403, description = "The caller lacks `iam:audit:read`.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed, or the time range is missing or too long.", body = Problem, content_type = "application/problem+json"),
        (status = 503, description = "The access log store is unavailable.", body = Problem, content_type = "application/problem+json"),
        (status = 504, description = "The access log store did not answer in time.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn list(
    State(state): State<IamState>,
    CallerPrincipal(caller): CallerPrincipal,
    ValidatedQuery(params): ValidatedQuery<ListAccessDecisionsParams>,
) -> Result<Json<AccessDecisionPageResponse>, Problem> {
    let page = list_access_decisions(&state, &caller, params).await?;
    Ok(Json(AccessDecisionPageResponse::from(&page)))
}

/// Reads one access decision.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without `iam:audit:read`, 404 for an
/// unknown decision, 422 for an id that is not a UUID, 503 or 504 for a failing log store.
#[utoipa::path(
    get,
    path = "/access-decisions/{id}",
    operation_id = "api_access_decisions_id_get",
    tag = "iam",
    summary = "Retrieves an access decision.",
    description = "Returns the access decision with the identifier. The log store is searched in a window of plus or minus two seconds around the timestamp that the UUID v7 carries, so an id that is not a UUID v7, or whose decision was not logged, is not found. The caller needs `iam:audit:read`, and the read is itself recorded in the security audit log as `access_log.read`.",
    security(("bearerAuth" = [])),
    params(("id" = String, Path, format = Uuid, description = "Access decision identifier")),
    responses(
        (status = 200, description = "The access decision.", body = AccessDecisionResponse),
        (status = 400, description = "Invalid identifier.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 403, description = "The caller lacks `iam:audit:read`.", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Access decision not found.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed.", body = Problem, content_type = "application/problem+json"),
        (status = 503, description = "The access log store is unavailable.", body = Problem, content_type = "application/problem+json"),
        (status = 504, description = "The access log store did not answer in time.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn get_one(
    State(state): State<IamState>,
    CallerPrincipal(caller): CallerPrincipal,
    ApiPath(id): ApiPath<String>,
) -> Result<Json<AccessDecisionResponse>, Problem> {
    let entry = find_access_decision(&state, &caller, parse_access_decision_id(&id)?)
        .await?
        .ok_or(IamError::NotFound)?;
    Ok(Json(AccessDecisionResponse::from(&entry)))
}

#[cfg(test)]
mod tests;
