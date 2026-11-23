//! Wire shapes of the grants of a role.

use iam_domain::{EntityVersion, RoleGrant, RoleId};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

use crate::query::get_role_permissions::RolePermissions;

/// Body of the operation that replaces the grants of a role.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, ToSchema, Validate)]
#[serde(deny_unknown_fields)]
#[schema(as = SetRolePermissionsRequest)]
pub struct SetRolePermissionsRequest {
    /// The new grant set: keys of an active catalogue and the four wildcard forms of a service
    /// that has a catalogue (`gql:{service}:{Type}.*`, `gql:{service}:*`,
    /// `rest:{service}:{METHOD} *`, `rest:{service}:*`). A key that repeats counts once; an empty
    /// list removes every grant.
    #[schema(max_items = 5000, example = json!(["rest:billing:GET /invoices", "gql:billing:*"]))]
    #[validate(length(max = 5000, message = "This value must contain 5000 items or fewer."))]
    pub keys: Vec<String>,
}

impl SetRolePermissionsRequest {
    /// The text that the idempotency digest of the request covers: the operation, the role, the
    /// version and the keys, so that a different body under the same key is a different request.
    #[must_use]
    pub fn canonical_form(&self, id: RoleId, expected: EntityVersion) -> String {
        format!(
            "role.permissions.set:{:?}",
            (id.to_string(), expected.value(), &self.keys)
        )
    }
}

/// One grant of a role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = RolePermission)]
pub struct RolePermissionResponse {
    /// The permission key or the wildcard pattern.
    #[schema(example = "rest:billing:GET /invoices")]
    pub key: String,
    /// The form of the key: `rest` or `gql`, or `reserved` for a reserved `iam:` key.
    #[schema(example = "rest")]
    pub kind: String,
    /// The service of the key.
    #[schema(example = "billing")]
    pub service: String,
    /// Whether the grant takes part in decisions; a grant to a key that left the catalogue is
    /// inactive.
    pub active: bool,
    /// Whether the grant is a wildcard pattern.
    pub wildcard: bool,
}

impl From<&RoleGrant> for RolePermissionResponse {
    fn from(stored: &RoleGrant) -> Self {
        Self {
            key: stored.grant.to_string(),
            kind: stored.grant.kind().as_str().to_owned(),
            service: stored.grant.service().to_string(),
            active: stored.active,
            wildcard: stored.grant.is_wildcard(),
        }
    }
}

/// The grants of a role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = RolePermissions)]
pub struct RolePermissionsResponse {
    /// The identifier of the role.
    #[schema(format = Uuid)]
    pub role_id: String,
    /// The version of the role.
    #[schema(minimum = 1)]
    pub version: i64,
    /// The grants in key order.
    pub permissions: Vec<RolePermissionResponse>,
}

impl From<&RolePermissions> for RolePermissionsResponse {
    fn from(stored: &RolePermissions) -> Self {
        Self {
            role_id: stored.id.to_string(),
            version: stored.version.value(),
            permissions: stored
                .grants
                .iter()
                .map(RolePermissionResponse::from)
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests;
