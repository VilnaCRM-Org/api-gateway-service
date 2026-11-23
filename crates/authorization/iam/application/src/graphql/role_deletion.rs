//! GraphQL input, payload and resolver of the role-deletion mutation.
//!
//! The resolver shares the use-case call of the REST handler, so both transports apply one set of
//! rules.

use async_graphql::{Context, ID, InputObject, SimpleObject};
use iam_domain::{ChangeReceipt, PolicyVersion};
use shared_application::http::Problem;

use super::{expected_version, idempotency_key, require_caller, state};
use crate::http::extract::VersionedWriteHeaders;
use crate::http::role::{delete_role, parse_role_id};

/// Input of the role-deletion mutation.
#[derive(Debug, InputObject)]
#[graphql(name = "DeleteRoleInput")]
pub struct DeleteRoleInput {
    /// The role to delete.
    pub id: ID,
    /// The version the caller read; required, and the deletion is refused when it is not the current one.
    pub expected_version: Option<i64>,
    /// Makes the deletion safe to repeat for 24 hours: 1 to 255 visible ASCII characters.
    pub idempotency_key: Option<String>,
}

/// The result of a role deletion.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "DeleteRolePayload")]
pub struct DeleteRolePayload {
    /// The identifier of the deleted role.
    pub id: ID,
    /// The final version of the role.
    pub version: i64,
    /// The policy version that the deletion produced.
    pub policy_version: Option<i64>,
    /// The number of assignments that the deletion revoked.
    pub revoked_assignments: i32,
}

impl From<&ChangeReceipt> for DeleteRolePayload {
    fn from(receipt: &ChangeReceipt) -> Self {
        Self {
            id: ID::from(receipt.target().target_id()),
            version: receipt.entity_version().value(),
            policy_version: receipt.policy_version().map(PolicyVersion::value),
            revoked_assignments: i32::try_from(receipt.revoked_assignments().unwrap_or_default())
                .unwrap_or(i32::MAX),
        }
    }
}

/// Deletes a role as the caller of the request.
pub(super) async fn delete_role_field(
    ctx: &Context<'_>,
    input: DeleteRoleInput,
) -> Result<DeleteRolePayload, Problem> {
    let caller = require_caller(ctx)?;
    let expected = expected_version(input.expected_version)?;
    let id = parse_role_id(input.id.as_str())?;
    let key = idempotency_key(input.idempotency_key.as_deref())?;
    let headers = VersionedWriteHeaders { expected, key };
    let receipt = delete_role(state(ctx)?, caller, id, headers).await?;
    Ok(DeleteRolePayload::from(&receipt))
}
