//! Wire shape of the request that resyncs the policy state (FR-78).

use serde::Deserialize;
use utoipa::ToSchema;
use validator::{Validate, ValidationError};

/// The longest reason an operator gives, in characters.
pub const MAX_REASON_CHARS: usize = 500;

/// Body of the operation that resyncs the policy state.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(as = ResyncPolicyRequest)]
pub struct ResyncPolicyRequest {
    /// Why the policy is resynced: one line of 1 to 500 characters, kept in the audit record and in
    /// `iam.policy.resynced`. A missing or blank reason is refused with 422.
    #[serde(default)]
    #[schema(
        min_length = 1,
        max_length = 500,
        example = "The state topic lost records after a broker failure."
    )]
    #[validate(
        length(
            min = 1,
            max = 500,
            message = "This value must contain between 1 and 500 characters."
        ),
        custom(function = validate_reason)
    )]
    pub reason: String,
}

impl ResyncPolicyRequest {
    /// The text that the idempotency digest of the request covers: the operation and the reason,
    /// so that a different reason under the same key is a different request.
    #[must_use]
    pub fn canonical_form(&self) -> String {
        format!("policy.resync:{:?}", self.reason)
    }
}

/// A reason is one line of text that says something: not blank, and without a control character.
fn validate_reason(reason: &str) -> Result<(), ValidationError> {
    if reason.trim().is_empty() || reason.chars().any(char::is_control) {
        let mut error = ValidationError::new("reason");
        error.message = Some("This value must be one line of text that says why.".into());
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
