//! GraphQL input, payload and resolver of the role-deletion mutation.
//!
//! The resolver shares the use-case call of the REST handler, so both transports apply one set of
//! rules.

use async_graphql::{Context, ID, InputObject, SimpleObject};
use iam_domain::{ChangeReceipt, PolicyVersion};
use shared_application::http::Problem;

use super::propagation::{PropagationObject, WriteOutcomeMapper, write_mode};
use super::{expected_version, idempotency_key, require_caller, state};
use crate::http::extract::VersionedWriteHeaders;
use crate::http::role::{BulkDeletion, RoleDeletion, delete_role, parse_role_id};

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
    /// What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions.
    pub consistency: Option<String>,
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
    /// What the deletion learned about the publication of its policy version.
    pub propagation: Option<PropagationObject>,
    /// The bulk operation that deletes a role with more assignments than `BULK_CHUNK_ENTITIES` in chunks, or null when the deletion committed in one change; for a bulk operation `version` is the version the role holds until the last chunk deletes it, `revokedAssignments` is the number of assignments it will revoke and `policyVersion` is null.
    pub bulk_operation_id: Option<ID>,
}

impl From<&ChangeReceipt> for DeleteRolePayload {
    fn from(receipt: &ChangeReceipt) -> Self {
        Self {
            id: ID::from(receipt.target().target_id()),
            version: receipt.entity_version().value(),
            policy_version: receipt.policy_version().map(PolicyVersion::value),
            revoked_assignments: i32::try_from(receipt.revoked_assignments().unwrap_or_default())
                .unwrap_or(i32::MAX),
            propagation: WriteOutcomeMapper::propagation(receipt),
            bulk_operation_id: None,
        }
    }
}

impl From<&BulkDeletion> for DeleteRolePayload {
    fn from(deletion: &BulkDeletion) -> Self {
        Self {
            id: ID::from(deletion.role.to_string()),
            version: deletion.version.value(),
            policy_version: None,
            revoked_assignments: i32::try_from(deletion.revoked_assignments()).unwrap_or(i32::MAX),
            propagation: None,
            bulk_operation_id: Some(ID::from(deletion.operation.id.to_string())),
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
    write_mode(input.consistency.as_deref())?;
    let headers = VersionedWriteHeaders { expected, key };
    Ok(match delete_role(state(ctx)?, caller, id, headers).await? {
        RoleDeletion::Committed(receipt) => DeleteRolePayload::from(&receipt),
        RoleDeletion::Bulk(deletion) => DeleteRolePayload::from(&deletion),
    })
}
