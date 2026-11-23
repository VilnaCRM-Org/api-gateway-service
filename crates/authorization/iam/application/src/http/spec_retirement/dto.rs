//! Wire shapes of the retirement of a specification version, which both specification forms
//! share.

use iam_domain::SpecId;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

/// Body of the operation that retires a specification version.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(as = RetireSpecRequest)]
pub struct RetireSpecRequest {
    /// Accepts that grants of keys that leave the catalogue become inactive. Without it, a
    /// retirement that would orphan grants is refused with 409 and lists them.
    #[serde(default)]
    pub confirm_orphans: bool,
}

impl RetireSpecRequest {
    /// The text that the idempotency digest of the request covers: the operation, the version and
    /// the body, so that a different body under the same key is a different request.
    #[must_use]
    pub fn canonical_form(&self, operation: &str, id: SpecId) -> String {
        format!(
            "{operation}.retire:{:?}",
            (id.to_string(), self.confirm_orphans)
        )
    }
}

/// The result of a retirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = SpecRetirement)]
pub struct SpecRetirementResponse {
    /// The identifier of the retired version.
    #[schema(format = Uuid)]
    pub id: String,
    /// The service the specification belongs to.
    #[schema(example = "billing")]
    pub service: String,
    /// `retired`.
    #[schema(example = "retired")]
    pub status: String,
    /// The policy version that the retirement produced.
    #[schema(minimum = 0)]
    pub policy_version: i64,
}

#[cfg(test)]
mod tests;
