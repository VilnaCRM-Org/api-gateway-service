//! Wire shapes of the activation of a GraphQL specification version.
//!
//! Each one keeps its schema constraints and its validator attributes on the same field so that
//! both stay equal.

use iam_domain::{InvalidPermissionKey, PermissionKey, SpecId};
use serde::{Deserialize, Serialize};
use shared_application::http::Violation;
use utoipa::ToSchema;
use validator::Validate;

use crate::error::IamError;

/// A coordinate that a version renames: the grants of the old key move to the new key.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema, Validate)]
#[serde(deny_unknown_fields)]
#[schema(as = KeyRename)]
pub struct KeyRenameDto {
    /// The old key, which the version no longer holds.
    #[schema(min_length = 1, max_length = 255, example = "gql:billing:Query.bills")]
    #[validate(length(
        min = 1,
        max = 255,
        message = "This value must contain between 1 and 255 characters."
    ))]
    pub from: String,
    /// The new key, which the version holds.
    #[schema(
        min_length = 1,
        max_length = 255,
        example = "gql:billing:Query.invoices"
    )]
    #[validate(length(
        min = 1,
        max = 255,
        message = "This value must contain between 1 and 255 characters."
    ))]
    pub to: String,
}

impl KeyRenameDto {
    /// The two keys of the rename.
    ///
    /// # Errors
    ///
    /// The violation of `renames[index].from` and of `renames[index].to` for each text that is
    /// not a permission key.
    fn parse(&self, index: usize) -> Result<(PermissionKey, PermissionKey), Vec<Violation>> {
        let from = parse_key(&self.from, format!("renames[{index}].from"));
        let to = parse_key(&self.to, format!("renames[{index}].to"));
        match (from, to) {
            (Ok(from), Ok(to)) => Ok((from, to)),
            (from, to) => Err([from.err(), to.err()].into_iter().flatten().collect()),
        }
    }
}

/// The key that the text names, or the violation of `property_path`.
fn parse_key(text: &str, property_path: String) -> Result<PermissionKey, Violation> {
    PermissionKey::parse(text).map_err(|error: InvalidPermissionKey| Violation {
        property_path,
        message: error.to_string(),
        code: error.code().to_owned(),
    })
}

/// Body of the operation that activates a GraphQL specification version.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(as = CreateGraphQlPermissionsRequest)]
pub struct CreateGraphQlPermissionsRequest {
    /// Accepts that grants of keys that leave the catalogue become inactive. Without it, an
    /// activation that would orphan grants is refused with 409 and lists them.
    #[serde(default)]
    pub confirm_orphans: bool,
    /// Accepts that keys lose the sensitive or the always-audit flag. Without it, an activation
    /// that would remove a flag is refused with 409 and lists the keys.
    #[serde(default)]
    pub confirm_flag_downgrade: bool,
    /// The coordinates that the version renames; the grants of each old key move to its new key
    /// before anything is orphaned.
    #[serde(default)]
    #[schema(max_items = 1000)]
    #[validate(length(max = 1000, message = "This value must contain 1000 items or fewer."))]
    #[validate(nested)]
    pub renames: Vec<KeyRenameDto>,
}

impl CreateGraphQlPermissionsRequest {
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
            "graphql_spec.activate:{:?}",
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

/// Parses `renames`, which the activations of both catalogue forms share.
///
/// # Errors
///
/// [`IamError::Invalid`] with the violations of every rename that is not a pair of permission
/// keys, in order.
pub(crate) fn parse_renames(
    renames: &[KeyRenameDto],
) -> Result<Vec<(PermissionKey, PermissionKey)>, IamError> {
    let parsed: Vec<_> = renames
        .iter()
        .enumerate()
        .map(|(index, rename)| rename.parse(index))
        .collect();
    let violations: Vec<Violation> = parsed
        .iter()
        .filter_map(|rename| rename.as_ref().err())
        .flatten()
        .cloned()
        .collect();
    if violations.is_empty() {
        Ok(parsed.into_iter().flatten().collect())
    } else {
        Err(IamError::Invalid(violations))
    }
}

/// The result of an activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = GraphQlPermissionsActivation)]
pub struct GraphQlPermissionsActivationResponse {
    /// The identifier of the activated version.
    #[schema(format = Uuid)]
    pub id: String,
    /// The service the schema belongs to.
    #[schema(example = "billing")]
    pub service: String,
    /// `active`.
    #[schema(example = "active")]
    pub status: String,
    /// The keys that the activation added to the catalogue, in key order; empty for a version
    /// that was active already.
    #[schema(example = json!(["gql:billing:Query.invoices"]))]
    pub created_keys: Vec<String>,
    /// The policy version that the activation produced; for a version that was active already,
    /// the current policy version.
    #[schema(minimum = 0)]
    pub policy_version: i64,
}

#[cfg(test)]
mod tests;
