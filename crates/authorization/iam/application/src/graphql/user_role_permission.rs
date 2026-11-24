//! GraphQL objects and the resolver of the effective permissions of a user.
//!
//! The resolver shares the use-case call and the response shapes of the REST handler, so both
//! transports apply one set of rules.

use async_graphql::{Context, ID, SimpleObject};
use shared_application::http::Problem;
use validator::Validate as _;

use super::{require_caller, state};
use crate::http::user_role_permission::dto::{
    EffectivePermissionResponse, GrantingRoleResponse, UserRolePermissionsParams,
    UserRolePermissionsResponse,
};
use crate::http::user_role_permission::find_user_role_permissions;

/// A role that grants an effective permission.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "GrantingRole")]
pub struct GrantingRoleObject {
    /// The identifier of the role.
    pub id: ID,
    /// The name of the role; null when the role is no longer stored.
    pub name: Option<String>,
}

impl From<GrantingRoleResponse> for GrantingRoleObject {
    fn from(response: GrantingRoleResponse) -> Self {
        Self {
            id: ID::from(response.id),
            name: response.name,
        }
    }
}

/// One key or wildcard that a user holds.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "EffectivePermission")]
pub struct EffectivePermissionObject {
    /// The permission key or the wildcard pattern.
    pub key: String,
    /// The form of the key: `rest` or `gql`, or `reserved` for a reserved `iam:` key.
    pub kind: String,
    /// The service of the key.
    pub service: String,
    /// Whether the entry is a wildcard pattern; a wildcard never covers a sensitive key.
    pub wildcard: bool,
    /// The roles of the active assignments that grant it, in identifier order.
    pub roles: Vec<GrantingRoleObject>,
    /// Where it is held: the single value `all` when a global assignment grants it, else the project ids.
    pub scopes: Vec<String>,
    /// The shortest expiry among the contributing assignments that expire, as an RFC 3339 UTC time; null when none of them expires.
    pub expires_at: Option<String>,
}

impl From<EffectivePermissionResponse> for EffectivePermissionObject {
    fn from(response: EffectivePermissionResponse) -> Self {
        Self {
            key: response.key,
            kind: response.kind,
            service: response.service,
            wildcard: response.wildcard,
            roles: response
                .roles
                .into_iter()
                .map(GrantingRoleObject::from)
                .collect(),
            scopes: response.scopes,
            expires_at: response.expires_at,
        }
    }
}

/// The effective permissions of a user.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "UserRolePermissions")]
pub struct UserRolePermissionsObject {
    /// The user whose permissions these are.
    pub user_id: ID,
    /// The policy version the permissions were composed at.
    pub policy_version: i64,
    /// The exact keys in key order, then the wildcard patterns.
    pub permissions: Vec<EffectivePermissionObject>,
}

impl From<UserRolePermissionsResponse> for UserRolePermissionsObject {
    fn from(response: UserRolePermissionsResponse) -> Self {
        Self {
            user_id: ID::from(response.user_id),
            policy_version: response.policy_version,
            permissions: response
                .permissions
                .into_iter()
                .map(EffectivePermissionObject::from)
                .collect(),
        }
    }
}

/// Reads the effective permissions of the user `user_id` as the caller of the request.
pub(super) async fn user_role_permissions_field(
    ctx: &Context<'_>,
    user_id: &ID,
    project_id: Option<String>,
    service: Option<String>,
) -> Result<UserRolePermissionsObject, Problem> {
    require_caller(ctx)?;
    let params = UserRolePermissionsParams {
        project_id,
        service,
    };
    params.validate()?;
    let view = find_user_role_permissions(state(ctx)?, user_id.as_str(), params).await?;
    Ok(UserRolePermissionsObject::from(
        UserRolePermissionsResponse::from(&view),
    ))
}

#[cfg(test)]
mod tests;
