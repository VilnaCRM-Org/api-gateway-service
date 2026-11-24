//! GraphQL input and resolver of the policy resync mutation.
//!
//! The resolver shares the use-case call and the response shape of the REST handler, so both
//! transports apply one set of rules.

use async_graphql::{Context, InputObject};
use shared_application::http::Problem;
use validator::Validate as _;

use super::bulk_operation::BulkOperationObject;
use super::{idempotency_key, require_caller, state};
use crate::http::bulk_operation::dto::BulkOperationResponse;
use crate::http::policy_resync::dto::ResyncPolicyRequest;
use crate::http::policy_resync::resync_policy;

/// Input of the policy resync mutation.
#[derive(Debug, InputObject)]
#[graphql(name = "ResyncPolicyInput")]
pub struct ResyncPolicyInput {
    /// Why the policy is resynced: one line of 1 to 500 characters, kept in the audit record and in `iam.policy.resynced`; a missing or blank reason fails with `VALIDATION_FAILED`.
    #[graphql(default)]
    pub reason: String,
    /// Makes the resync safe to repeat for 24 hours: 1 to 255 visible ASCII characters.
    pub idempotency_key: Option<String>,
}

/// Resyncs the policy as the caller of the request and returns the bulk operation that
/// republishes the state.
pub(super) async fn resync_policy_field(
    ctx: &Context<'_>,
    input: ResyncPolicyInput,
) -> Result<BulkOperationObject, Problem> {
    let caller = require_caller(ctx)?;
    let key = idempotency_key(input.idempotency_key.as_deref())?;
    let request = ResyncPolicyRequest {
        reason: input.reason,
    };
    request.validate()?;
    let operation = resync_policy(state(ctx)?, caller, key, &request).await?;
    Ok(BulkOperationObject::from(BulkOperationResponse::from(
        operation,
    )))
}

#[cfg(test)]
mod tests;
