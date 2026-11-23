//! Wire shapes of the activation of an `OpenAPI` specification version.
//!
//! The renames are those of the activation of a GraphQL version: [`KeyRenameDto`] is shared, the
//! keys it holds are `rest:{service}:{METHOD} {template}` here.

use iam_domain::{PermissionKey, SpecId};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

use crate::error::IamError;
use crate::http::graphql_activation::dto::{KeyRenameDto, parse_renames};

/// Body of the operation that activates an `OpenAPI` specification version.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(as = CreateRestPermissionsRequest)]
pub struct CreateRestPermissionsRequest {
    /// Accepts that grants of keys that leave the catalogue become inactive. Without it, an
    /// activation that would orphan grants is refused with 409 and lists them.
    #[serde(default)]
    pub confirm_orphans: bool,
    /// Accepts that keys lose the sensitive or the always-audit flag. Without it, an activation
    /// that would remove a flag is refused with 409 and lists the keys.
    #[serde(default)]
    pub confirm_flag_downgrade: bool,
    /// The operations that the version renames; the grants of each old key move to its new key
    /// before anything is orphaned.
    #[serde(default)]
    #[schema(max_items = 1000)]
    #[validate(length(max = 1000, message = "This value must contain 1000 items or fewer."))]
    #[validate(nested)]
    pub renames: Vec<KeyRenameDto>,
}

impl CreateRestPermissionsRequest {
    /// The text that the idempotency digest of the request covers: the operation, the version and
    /// the body, so that a different body under the same key is a different request.
    #[must_use]
    pub fn canonical_form(&self, id: SpecId) -> String {
        let renames: Vec<(&str, &str)> = self
            .renames
            .iter()
            .map(|rename| (rename.from.as_str(), rename.to.as_str()))
            .collect();
        format!(
            "openapi_spec.activate:{:?}",
            (
                id.to_string(),
                self.confirm_orphans,
                self.confirm_flag_downgrade,
                renames
            )
        )
    }

    /// Parses the renames.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with the violations of every rename that is not a pair of permission
    /// keys, in order.
    pub fn parse(&self) -> Result<Vec<(PermissionKey, PermissionKey)>, IamError> {
        parse_renames(&self.renames)
    }
}

/// The result of an activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = RestPermissionsActivation)]
pub struct RestPermissionsActivationResponse {
    /// The identifier of the activated version.
    #[schema(format = Uuid)]
    pub id: String,
    /// The service the document belongs to.
    #[schema(example = "billing")]
    pub service: String,
    /// `active`.
    #[schema(example = "active")]
    pub status: String,
    /// The keys that the activation added to the catalogue, in key order; empty for a version
    /// that was active already.
    #[schema(example = json!(["rest:billing:GET /invoices"]))]
    pub created_keys: Vec<String>,
    /// The policy version that the activation produced; for a version that was active already,
    /// the current policy version.
    #[schema(minimum = 0)]
    pub policy_version: i64,
}

#[cfg(test)]
mod tests;
