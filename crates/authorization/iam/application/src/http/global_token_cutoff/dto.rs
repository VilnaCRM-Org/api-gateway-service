//! Wire shape of the operation that sets the global token cut-off (FR-1, FR-17).

use std::collections::BTreeMap;

use serde::Deserialize;
use utoipa::ToSchema;
use validator::{Validate, ValidationError, ValidationErrors};

/// Body of the operation that sets the global token cut-off: an empty object, because the cut-off
/// instant is the commit time of the request plus a 2-second margin.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, ToSchema)]
#[serde(transparent)]
#[schema(as = SetGlobalTokenCutoffRequest, example = json!({}))]
pub struct SetGlobalTokenCutoffRequest(pub BTreeMap<String, String>);

impl SetGlobalTokenCutoffRequest {
    /// The text that the idempotency digest of the request covers: the operation alone.
    #[must_use]
    pub const fn canonical_form() -> &'static str {
        "global_token.cut_off"
    }
}

impl Validate for SetGlobalTokenCutoffRequest {
    /// The body must be an empty object: the operation takes no input.
    fn validate(&self) -> Result<(), ValidationErrors> {
        if self.0.is_empty() {
            return Ok(());
        }
        let mut error = ValidationError::new("empty");
        error.message = Some("This object must be empty.".into());
        let mut errors = ValidationErrors::new();
        errors.add("body", error);
        Err(errors)
    }
}

#[cfg(test)]
mod tests;
