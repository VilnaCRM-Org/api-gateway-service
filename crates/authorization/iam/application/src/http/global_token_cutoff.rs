//! REST handler that sets the global token cut-off, and the use-case call that the GraphQL
//! resolver shares (FR-1, FR-17, FR-70).
//!
//! A handler takes the IAM state and the problem-aware extractors only (`ValidatedJson`, the IAM
//! extractors `CallerPrincipal` and `IdempotencyKeyHeader`); the test of the `handler` module
//! checks every handler against that rule.

pub mod dto;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use iam_domain::{ChangeId, ChangeReceipt, IdempotencyKey, IdempotencyRequest};
use shared_application::http::{Problem, ValidatedJson};

use super::IamState;
use super::extract::{CallerPrincipal, IdempotencyKeyHeader};
use super::response::{WriteHeaders, change_headers, write_status};
use super::session_revocation::dto::RevocationResultResponse;
use super::user_role::find_replay;
use crate::command::set_global_token_cutoff::SetGlobalTokenCutoffCommand;
use crate::principal::Principal;
use crate::query::get_change_receipt::GetChangeReceiptQuery;
use dto::SetGlobalTokenCutoffRequest;

/// Sets the global cut-off as `caller`, or replays the one that `key` already committed; REST and
/// GraphQL share it.
///
/// The receipt of the change is read back, because a command returns no data.
///
/// # Errors
///
/// The problem of a refused request: 422 for a key reused for another request, 500 for a storage
/// failure.
pub(crate) async fn set_global_token_cutoff(
    state: &IamState,
    caller: &Principal,
    key: Option<IdempotencyKey>,
) -> Result<ChangeReceipt, Problem> {
    let actor = caller.actor();
    let idempotency = key.map(|key| IdempotencyRequest {
        key,
        request_digest: state
            .request_digester
            .digest(SetGlobalTokenCutoffRequest::canonical_form()),
    });
    if let Some(replayed) = find_replay(state, &actor, idempotency.as_ref()).await? {
        return Ok(replayed);
    }
    let change_id = ChangeId::from_uuid(state.uuid_generator.generate());
    let command = SetGlobalTokenCutoffCommand {
        change_id,
        actor,
        idempotency,
    };
    state.command_bus.dispatch(command).await?;
    Ok(state
        .query_bus
        .ask(GetChangeReceiptQuery { change_id })
        .await?)
}

/// Sets the global token cut-off.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without `iam:revoke:global`, 422 for a
/// reused idempotency key, 500 when the storage fails.
#[utoipa::path(
    post,
    path = "/global-token-cutoffs",
    operation_id = "api_global_token_cutoffs_post",
    tag = "iam",
    summary = "Sets the global token cut-off.",
    description = "Refuses every token issued before the commit time plus 2 seconds, for an emergency key compromise: the cut-off row and its state record `revocation/global` are written, the next policy version is committed, and `iam.global_tokens.cut_off` and an audit record are written in the same transaction. A cut-off never moves back. The operation needs the reserved key `iam:revoke:global`. The body is an empty object. A repeated `Idempotency-Key` within 24 hours returns the original result.",
    security(("bearerAuth" = [])),
    params(
        ("Idempotency-Key" = Option<String>, Header, description = "Makes the write safe to repeat for 24 hours; 1 to 255 visible ASCII characters.")
    ),
    request_body(content = SetGlobalTokenCutoffRequest, content_type = "application/json"),
    responses(
        (
            status = 201,
            description = "The global cut-off was set.",
            body = RevocationResultResponse,
            headers(
                ("etag" = String, description = "The version of the change record in double quotes."),
                ("iam-policy-version" = String, description = "The policy version that the change produced."),
                ("iam-policy-offset" = String, description = "The offset at which Kafka stored the `__head` record of the policy version; present when the change was acknowledged.")
            )
        ),
        (
            status = 202,
            description = "The change is committed and its policy version was not acknowledged by Kafka within `PUBLISH_WAIT_TIMEOUT`; it may not be in force on the gateway yet.",
            body = RevocationResultResponse,
            headers(
                ("etag" = String, description = "The version of the change record in double quotes."),
                ("iam-policy-version" = String, description = "The policy version that the change produced."),
                ("iam-propagation-status" = String, description = "`committed_pending_propagation`.")
            )
        ),
        (status = 400, description = "Invalid input.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 403, description = "The caller does not hold `iam:revoke:global`.", body = Problem, content_type = "application/problem+json"),
        (status = 413, description = "Request body too large.", body = Problem, content_type = "application/problem+json"),
        (status = 415, description = "Unsupported media type.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed, or the idempotency key was used for another request.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn create(
    State(state): State<IamState>,
    CallerPrincipal(caller): CallerPrincipal,
    IdempotencyKeyHeader(key): IdempotencyKeyHeader,
    ValidatedJson(_body): ValidatedJson<SetGlobalTokenCutoffRequest>,
) -> Result<(StatusCode, WriteHeaders, Json<RevocationResultResponse>), Problem> {
    let receipt = set_global_token_cutoff(&state, &caller, key).await?;
    Ok((
        write_status(&receipt, StatusCode::CREATED),
        change_headers(&receipt),
        Json(RevocationResultResponse::from(&receipt)),
    ))
}

#[cfg(test)]
mod tests;
