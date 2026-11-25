//! REST handlers that read the security audit log, and the use-case calls that the GraphQL
//! resolvers share.
//!
//! A handler takes the IAM state and the problem-aware extractors only (`ApiPath`,
//! `ValidatedQuery`, the IAM extractor `CallerPrincipal`); the test of the `handler` module checks
//! every handler against that rule. Every successful read is recorded in the log by the use case.

pub mod dto;

use axum::Json;
use axum::extract::State;
use iam_domain::{
    AuditChainHead, ChainVerification, SecurityAuditEventId, StoredSecurityAuditEvent,
};
use shared_application::http::{ApiPath, Problem, ValidatedQuery, Violation};

use super::IamState;
use super::extract::CallerPrincipal;
use crate::error::IamError;
use crate::principal::Principal;
use crate::query::get_security_audit_event::GetSecurityAuditEventQuery;
use crate::query::get_security_audit_events::SecurityAuditEventPage;
use crate::query::verify_security_audit_chain::VerifySecurityAuditChainQuery;
use dto::{
    ChainVerificationResponse, ListSecurityAuditEventsParams, SecurityAuditEventPageResponse,
    SecurityAuditEventResponse, VerifyChainParams,
};

/// The security audit record id of a path or an argument.
///
/// # Errors
///
/// [`IamError::Invalid`] with a violation of `id` when the text is not a UUID.
pub(crate) fn parse_security_audit_event_id(text: &str) -> Result<SecurityAuditEventId, IamError> {
    SecurityAuditEventId::parse(text).map_err(|_error| {
        IamError::Invalid(vec![Violation {
            property_path: "id".to_owned(),
            message: "This value is not a valid UUID.".to_owned(),
            code: "uuid".to_owned(),
        }])
    })
}

/// The audit record with the identifier, read as `caller`; none when it is unknown.
///
/// # Errors
///
/// The 500 problem of a storage failure, which includes a read that cannot be audited.
pub(crate) async fn find_security_audit_event(
    state: &IamState,
    caller: &Principal,
    id: SecurityAuditEventId,
) -> Result<Option<StoredSecurityAuditEvent>, Problem> {
    let query = GetSecurityAuditEventQuery {
        actor: caller.actor(),
        id,
    };
    Ok(state.query_bus.ask(query).await?)
}

/// One page of audit records for validated parameters, read as `caller`.
///
/// # Errors
///
/// The 422 problem of an invalid parameter, the 500 problem of a storage failure, which includes
/// a search that cannot be audited.
pub(crate) async fn list_security_audit_events(
    state: &IamState,
    caller: &Principal,
    params: ListSecurityAuditEventsParams,
) -> Result<SecurityAuditEventPage, Problem> {
    let query = params.into_query(caller.actor())?;
    Ok(state.query_bus.ask(query).await?)
}

/// The verification of the whole audit chain against `anchors`, read as `caller`.
///
/// # Errors
///
/// The 500 problem of a storage failure, which includes a verification that cannot be audited.
pub(crate) async fn verify_security_audit_chain(
    state: &IamState,
    caller: &Principal,
    anchors: Vec<AuditChainHead>,
) -> Result<ChainVerification, Problem> {
    let query = VerifySecurityAuditChainQuery {
        actor: caller.actor(),
        anchors,
    };
    Ok(state.query_bus.ask(query).await?)
}

/// Searches the security audit log.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without `iam:audit:read`, 422 for an invalid
/// parameter.
#[utoipa::path(
    get,
    path = "/security-audit-events",
    operation_id = "api_security_audit_events_get",
    tag = "iam",
    summary = "Searches the security audit log.",
    description = "Returns one page of the audit records that meet every filter given, newest first, with the actor, the action, the target, the summaries before and after, the outcome, the resulting `policyVersion` and the place in the hash chain. Committed changes and rejected attempts are both returned. The caller needs `iam:audit:read`, and the search is itself recorded in the log as `security_audit.list`. `nextCursor` goes into `after` for the next, older page.",
    security(("bearerAuth" = [])),
    params(ListSecurityAuditEventsParams),
    responses(
        (status = 200, description = "One page of audit records.", body = SecurityAuditEventPageResponse),
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
    CallerPrincipal(caller): CallerPrincipal,
    ValidatedQuery(params): ValidatedQuery<ListSecurityAuditEventsParams>,
) -> Result<Json<SecurityAuditEventPageResponse>, Problem> {
    let page = list_security_audit_events(&state, &caller, params).await?;
    Ok(Json(SecurityAuditEventPageResponse::from(&page)))
}

/// Verifies the security audit hash chain.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without `iam:audit:read`, 422 for an invalid
/// anchor.
#[utoipa::path(
    get,
    path = "/security-audit-events/chain-verification",
    operation_id = "api_security_audit_events_chain_verification_get",
    tag = "iam",
    summary = "Verifies the security audit hash chain.",
    description = "Recomputes the hash chain from the first record: every sequence number follows the one before it, every `prevHash` is the hash of the record before it and every `hash` is the digest of the stored values of its record. The result is `valid` with the number of records checked, or `invalid` with the id and the sequence number of the first record where the chain breaks and the cause. `anchors` are `<seq>:<hash>` pairs published as `iam.security_audit.anchored` events and kept outside the database; the chain is `invalid` at an anchored record whose hash differs, which detects a chain that was rewritten and recomputed as a whole. The caller needs `iam:audit:read`, and the verification is itself recorded in the log as `security_audit.verify`.",
    security(("bearerAuth" = [])),
    params(VerifyChainParams),
    responses(
        (status = 200, description = "The result of the verification.", body = ChainVerificationResponse),
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
pub async fn verify(
    State(state): State<IamState>,
    CallerPrincipal(caller): CallerPrincipal,
    ValidatedQuery(params): ValidatedQuery<VerifyChainParams>,
) -> Result<Json<ChainVerificationResponse>, Problem> {
    let anchors = params.into_anchors()?;
    let verification = verify_security_audit_chain(&state, &caller, anchors).await?;
    Ok(Json(ChainVerificationResponse::from(&verification)))
}

/// Reads one audit record.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without `iam:audit:read`, 404 for an unknown
/// record, 422 for an id that is not a UUID.
#[utoipa::path(
    get,
    path = "/security-audit-events/{id}",
    operation_id = "api_security_audit_events_id_get",
    tag = "iam",
    summary = "Retrieves a security audit record.",
    description = "Returns the audit record with the identifier and its place in the hash chain. The caller needs `iam:audit:read`, and the read is itself recorded in the log as `security_audit.read`.",
    security(("bearerAuth" = [])),
    params(("id" = String, Path, format = Uuid, description = "Audit record identifier")),
    responses(
        (status = 200, description = "The audit record.", body = SecurityAuditEventResponse),
        (status = 400, description = "Invalid identifier.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 403, description = "The caller lacks `iam:audit:read`.", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Audit record not found.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn get_one(
    State(state): State<IamState>,
    CallerPrincipal(caller): CallerPrincipal,
    ApiPath(id): ApiPath<String>,
) -> Result<Json<SecurityAuditEventResponse>, Problem> {
    let record = find_security_audit_event(&state, &caller, parse_security_audit_event_id(&id)?)
        .await?
        .ok_or(IamError::NotFound)?;
    Ok(Json(SecurityAuditEventResponse::from(&record)))
}

#[cfg(test)]
mod tests;
