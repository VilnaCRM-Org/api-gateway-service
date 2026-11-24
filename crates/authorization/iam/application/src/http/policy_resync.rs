//! REST handler that resyncs the policy state, and the use-case call that the GraphQL resolver
//! shares (FR-78).
//!
//! A handler takes the IAM state and the problem-aware extractors only (`ValidatedJson`, the IAM
//! extractors `CallerPrincipal` and `IdempotencyKeyHeader`); the test of the `handler` module
//! checks every handler against that rule.

pub mod dto;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::LOCATION;
use axum::response::AppendHeaders;
use iam_domain::{
    BulkOperationId, BulkOperationParts, ChangeId, ChangeReceipt, IdempotencyKey,
    IdempotencyRequest,
};
use shared_application::http::{Problem, ValidatedJson};

use super::IamState;
use super::bulk_operation::dto::BulkOperationResponse;
use super::bulk_operation::{BULK_OPERATIONS_PATH, find_bulk_operation};
use super::extract::{CallerPrincipal, IdempotencyKeyHeader};
use super::response::WriteHeaders;
use super::user_role::find_replay;
use crate::command::resync_policy::ResyncPolicyCommand;
use crate::error::IamError;
use crate::principal::Principal;
use crate::query::get_change_receipt::GetChangeReceiptQuery;
use dto::ResyncPolicyRequest;

/// Resyncs the policy as `caller`, or replays the resync that `key` already started; REST and
/// GraphQL share it.
///
/// It returns the bulk operation that republishes the state, as it was recorded, because a command
/// returns no data.
///
/// # Errors
///
/// The problem of a refused request: 409 for a policy without entities, a log epoch that changed
/// meanwhile or a topic version at the end of its range, 422 for a key reused for another request,
/// 500 for a storage failure.
pub(crate) async fn resync_policy(
    state: &IamState,
    caller: &Principal,
    key: Option<IdempotencyKey>,
    request: &ResyncPolicyRequest,
) -> Result<BulkOperationParts, Problem> {
    let actor = caller.actor();
    let idempotency = key.map(|key| IdempotencyRequest {
        key,
        request_digest: state.request_digester.digest(&request.canonical_form()),
    });
    if let Some(replayed) = find_replay(state, &actor, idempotency.as_ref()).await? {
        return operation_of(state, &replayed).await;
    }
    let change_id = ChangeId::from_uuid(state.uuid_generator.generate());
    let command = ResyncPolicyCommand {
        change_id,
        actor,
        reason: request.reason.clone(),
        idempotency,
    };
    state.command_bus.dispatch(command).await?;
    let receipt = state
        .query_bus
        .ask(GetChangeReceiptQuery { change_id })
        .await?;
    operation_of(state, &receipt).await
}

/// The bulk operation that the receipt of a committed resync names.
async fn operation_of(
    state: &IamState,
    receipt: &ChangeReceipt,
) -> Result<BulkOperationParts, Problem> {
    let id = BulkOperationId::parse(receipt.target().target_id()).map_err(IamError::from)?;
    Ok(find_bulk_operation(state, id)
        .await?
        .ok_or(IamError::NotFound)?)
}

/// The path of the bulk operation, the `Location` of the 202 response.
pub(crate) fn location(operation: &BulkOperationParts) -> String {
    format!("{BULK_OPERATIONS_PATH}/{}", operation.id)
}

/// Resyncs the policy state.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without `iam:policy:resync`, 409 for a policy
/// without entities or a log epoch that changed meanwhile, 422 for a missing or invalid reason or a
/// reused idempotency key, 500 when the storage fails.
#[utoipa::path(
    post,
    path = "/policy-resyncs",
    operation_id = "api_policy_resyncs_post",
    tag = "iam",
    summary = "Resyncs the policy state.",
    description = "Republishes the complete current policy as a new log epoch, for the operator who repairs the state topic after an incident: the log epoch moves on, the policy version continues above both the stored version and the highest version of the topic, and a bulk operation of kind `resync` publishes the state of every entity in ordered chunks under the new epoch. `reason` is required and is kept in the audit record and in `iam.policy.resynced`. The operation needs the reserved key `iam:policy:resync`. The response is 202 with the `Location` of the bulk operation; follow it until the operation is `completed`. A repeated `Idempotency-Key` with the same body within 24 hours returns the original bulk operation and starts no second resync. A gateway pod repairs its own cached policy from the topic, so the contract offers no operation that clears that cache.",
    security(("bearerAuth" = [])),
    params(("Idempotency-Key" = Option<String>, Header, description = "Makes the resync safe to repeat for 24 hours; 1 to 255 visible ASCII characters.")),
    request_body(content = ResyncPolicyRequest, content_type = "application/json"),
    responses(
        (
            status = 202,
            description = "The resync started: the bulk operation that republishes the state.",
            body = BulkOperationResponse,
            headers(("location" = String, description = "Path of the bulk operation."))
        ),
        (status = 400, description = "Invalid input.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 403, description = "The caller does not hold `iam:policy:resync`.", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The policy holds no entity, or the log epoch changed while the resync started.", body = Problem, content_type = "application/problem+json"),
        (status = 413, description = "Request body too large.", body = Problem, content_type = "application/problem+json"),
        (status = 415, description = "Unsupported media type.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed: a missing or invalid reason, an invalid idempotency key, or the idempotency key was used for another request.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn create(
    State(state): State<IamState>,
    CallerPrincipal(caller): CallerPrincipal,
    IdempotencyKeyHeader(key): IdempotencyKeyHeader,
    ValidatedJson(body): ValidatedJson<ResyncPolicyRequest>,
) -> Result<(StatusCode, WriteHeaders, Json<BulkOperationResponse>), Problem> {
    let operation = resync_policy(&state, &caller, key, &body).await?;
    let headers = AppendHeaders(vec![(LOCATION, location(&operation))]);
    Ok((
        StatusCode::ACCEPTED,
        headers,
        Json(BulkOperationResponse::from(operation)),
    ))
}

#[cfg(test)]
mod tests;
