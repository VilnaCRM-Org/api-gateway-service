//! GraphQL input, object and resolvers of the grants of a role.
//!
//! The resolvers share the use-case calls and the DTOs of the REST handlers, so both transports
//! apply one set of rules.

use async_graphql::{Context, ID, InputObject, SimpleObject};
use iam_domain::RoleGrant;
use shared_application::http::Problem;
use validator::Validate as _;

use super::propagation::{WriteOutcomeMapper, write_mode};
use super::{RoleObject, expected_version, idempotency_key, require_caller, state};
use crate::error::IamError;
use crate::http::dto::RoleResponse;
use crate::http::extract::VersionedWriteHeaders;
use crate::http::role::{find_role, parse_role_id};
use crate::http::role_permission::dto::{RolePermissionResponse, SetRolePermissionsRequest};
use crate::http::role_permission::{find_role_permissions, set_role_permissions};

/// Input of the mutation that replaces the grants of a role.
#[derive(Debug, InputObject)]
#[graphql(name = "SetRolePermissionsInput")]
pub struct SetRolePermissionsInput {
    /// The role to change.
    pub id: ID,
    /// The version the caller read; required, and the replacement is refused when it is not the current one.
    pub expected_version: Option<i64>,
    /// The new grant set: keys of an active catalogue and the four wildcard forms of a service that has a catalogue; at most 5,000. A key that repeats counts once and an empty list removes every grant.
    pub keys: Vec<String>,
    /// Makes the replacement safe to repeat for 24 hours: 1 to 255 visible ASCII characters.
    pub idempotency_key: Option<String>,
    /// What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions.
    pub consistency: Option<String>,
}

/// One grant of a role.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "RolePermission")]
pub struct RolePermissionObject {
    /// The permission key or the wildcard pattern.
    pub key: String,
    /// The form of the key: `rest` or `gql`, or `reserved` for a reserved `iam:` key.
    pub kind: String,
    /// The service of the key.
    pub service: String,
    /// Whether the grant takes part in decisions; a grant to a key that left the catalogue is inactive.
    pub active: bool,
    /// Whether the grant is a wildcard pattern.
    pub wildcard: bool,
}

impl From<RolePermissionResponse> for RolePermissionObject {
    fn from(response: RolePermissionResponse) -> Self {
        Self {
            key: response.key,
            kind: response.kind,
            service: response.service,
            active: response.active,
            wildcard: response.wildcard,
        }
    }
}

impl From<&RoleGrant> for RolePermissionObject {
    fn from(stored: &RoleGrant) -> Self {
        Self::from(RolePermissionResponse::from(stored))
    }
}

/// Replaces the grants of a role as the caller of the request and returns the changed role.
pub(super) async fn set_role_permissions_field(
    ctx: &Context<'_>,
    input: SetRolePermissionsInput,
) -> Result<RoleObject, Problem> {
    let caller = require_caller(ctx)?;
    let expected = expected_version(input.expected_version)?;
    let id = parse_role_id(input.id.as_str())?;
    let key = idempotency_key(input.idempotency_key.as_deref())?;
    let request = SetRolePermissionsRequest { keys: input.keys };
    request.validate()?;
    write_mode(input.consistency.as_deref())?;
    let headers = VersionedWriteHeaders { expected, key };
    let state = state(ctx)?;
    let (_permissions, receipt) = set_role_permissions(state, caller, id, headers, request).await?;
    let role = find_role(state, id).await?.ok_or(IamError::NotFound)?;
    Ok(RoleObject {
        propagation: WriteOutcomeMapper::propagation(&receipt),
        ..RoleObject::from(RoleResponse::from(role))
    })
}

/// The grants of the role `id`, as the `permissions` field of a role.
pub(super) async fn role_permissions_field(
    ctx: &Context<'_>,
    id: &ID,
) -> Result<Vec<RolePermissionObject>, Problem> {
    require_caller(ctx)?;
    let permissions = find_role_permissions(state(ctx)?, parse_role_id(id.as_str())?)
        .await?
        .ok_or(IamError::NotFound)?;
    Ok(permissions
        .grants
        .iter()
        .map(RolePermissionObject::from)
        .collect())
}

#[cfg(test)]
mod tests;
