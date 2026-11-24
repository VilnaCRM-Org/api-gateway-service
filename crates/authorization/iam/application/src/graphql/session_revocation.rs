//! GraphQL input, payload and resolver of the session revocation mutation.
//!
//! The resolver shares the use-case call and the response shape of the REST handler, so both
//! transports apply one set of rules.

use async_graphql::{Context, ID, InputObject, SimpleObject};
use shared_application::http::Problem;
use validator::Validate as _;

use super::propagation::{PropagationObject, WriteOutcomeMapper, write_mode};
use super::{idempotency_key, require_caller, state};
use crate::http::session_revocation::dto::RevokeSessionsRequest;
use crate::http::session_revocation::revoke_sessions;

/// Input of the session revocation mutation.
#[derive(Debug, InputObject)]
#[graphql(name = "RevokeSessionsInput")]
pub struct RevokeSessionsInput {
    /// The user whose sessions or tokens are revoked.
    pub user_id: ID,
    /// The sessions to revoke, at most 100, each 1 to 255 visible ASCII characters; an empty or missing list sets the cut-off of every token of the user instead.
    #[graphql(default)]
    pub session_ids: Vec<String>,
    /// Makes the revocation safe to repeat for 24 hours: 1 to 255 visible ASCII characters.
    pub idempotency_key: Option<String>,
    /// What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions.
    pub consistency: Option<String>,
}

/// The result of a revocation write.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "RevocationPayload")]
pub struct RevocationPayload {
    /// What the audit record of the change targets: the first revoked session's revocation, the user of a cut-off, or `current` for the global cut-off.
    pub id: ID,
    /// The policy version that the change produced.
    pub policy_version: Option<i64>,
    /// What the change learned about the publication of its policy version.
    pub propagation: Option<PropagationObject>,
}

/// Revokes sessions as the caller of the request.
pub(super) async fn revoke_sessions_field(
    ctx: &Context<'_>,
    input: RevokeSessionsInput,
) -> Result<RevocationPayload, Problem> {
    let caller = require_caller(ctx)?;
    let key = idempotency_key(input.idempotency_key.as_deref())?;
    write_mode(input.consistency.as_deref())?;
    let request = RevokeSessionsRequest {
        user_id: input.user_id.to_string(),
        session_ids: input.session_ids,
    };
    request.validate()?;
    let receipt = revoke_sessions(state(ctx)?, caller, key, &request).await?;
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
