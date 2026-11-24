//! GraphQL input and resolver of the global token cut-off mutation.
//!
//! The resolver shares the use-case call and the response shape of the REST handler, so both
//! transports apply one set of rules.

use async_graphql::{Context, ID, InputObject};
use shared_application::http::Problem;

use super::propagation::{WriteOutcomeMapper, write_mode};
use super::session_revocation::RevocationPayload;
use super::{idempotency_key, require_caller, state};
use crate::http::global_token_cutoff::set_global_token_cutoff;

/// Input of the global token cut-off mutation.
#[derive(Debug, Default, InputObject)]
#[graphql(name = "SetGlobalTokenCutoffInput")]
pub struct SetGlobalTokenCutoffInput {
    /// Makes the write safe to repeat for 24 hours: 1 to 255 visible ASCII characters.
    pub idempotency_key: Option<String>,
    /// What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions.
    pub consistency: Option<String>,
}

/// Sets the global token cut-off as the caller of the request.
pub(super) async fn set_global_token_cutoff_field(
    ctx: &Context<'_>,
    input: SetGlobalTokenCutoffInput,
) -> Result<RevocationPayload, Problem> {
    let caller = require_caller(ctx)?;
    let key = idempotency_key(input.idempotency_key.as_deref())?;
    write_mode(input.consistency.as_deref())?;
    let receipt = set_global_token_cutoff(state(ctx)?, caller, key).await?;
    Ok(RevocationPayload {
        id: ID::from(receipt.target().target_id()),
        policy_version: receipt
            .policy_version()
            .map(iam_domain::PolicyVersion::value),
        propagation: WriteOutcomeMapper::propagation(&receipt),
    })
}

#[cfg(test)]
mod tests;
