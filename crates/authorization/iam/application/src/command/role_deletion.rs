//! The pieces of a role deletion that the command and the bulk path share: the revocation of one
//! assignment, the audit records of the deletion and the page of assignments to revoke.

use std::time::SystemTime;

use iam_domain::{
    AuditAction, AuditOutcome, AuditSummary, AuditTarget, ChangeStatement, EventEnvelope,
    RevocationCause, RoleId, RoleName, RoleParts, RoleStamp, SecurityAuditEvent,
    SecurityAuditEventId, SecurityAuditEventParts, UserRole, UserRoleId, UserRolePageQuery,
    UserRoleParts, UserRoleStamp, UserRoleStatement,
};
use shared_domain::UuidGenerator;

use crate::error::IamError;

/// The audit action of a deleted role.
const AUDIT_ACTION: &str = "role.delete";

/// The audit action of an assignment that the deletion of its role revoked.
const REVOKE_AUDIT_ACTION: &str = "user_role.revoke";

/// The number of assignments read per page.
pub(crate) const PAGE_LIMIT: u32 = 100;

/// The write of one revoked assignment: its statement, its events and its audit record.
pub(crate) struct Revocation {
    pub(crate) statement: ChangeStatement,
    pub(crate) events: Vec<EventEnvelope>,
    pub(crate) audit: SecurityAuditEvent,
}

/// The page of assignments of `role_id` after the cursor, expired ones included.
pub(crate) const fn page_query(
    role_id: RoleId,
    after: Option<UserRoleId>,
    now: SystemTime,
) -> UserRolePageQuery {
    UserRolePageQuery {
        limit: PAGE_LIMIT,
        after,
        subject_kind: None,
        subject_id: None,
        role_id: Some(role_id),
        project_id: None,
        include_expired: true,
        now,
    }
}

/// The revocation of one assignment, at the version it was read at, with its own event
/// identifier.
pub(crate) fn revocation(
    ids: &dyn UuidGenerator,
    mut user_role: UserRole,
    role_name: RoleName,
    role_stamp: &RoleStamp,
) -> Result<Revocation, IamError> {
    let before = user_role.parts().clone();
    let stamp = UserRoleStamp {
        event_id: ids.generate(),
        actor: role_stamp.actor.clone(),
        occurred_at: role_stamp.occurred_at,
    };
    user_role.revoke(
        Some(before.version),
        role_name,
        RevocationCause::RoleDeleted,
        stamp.clone(),
    )?;
    Ok(Revocation {
        events: user_role.pull_envelopes()?,
        audit: revoke_audit(ids, &before, user_role.parts(), &stamp)?,
        statement: ChangeStatement::SaveUserRole(Box::new(UserRoleStatement::update(
            &user_role,
            before.version,
        ))),
    })
}

/// The summaries of a role before its deletion and after it, for the audit record.
pub(crate) fn summaries(before: &RoleParts, after: &RoleParts, revoked: u32) -> (String, String) {
    (
        format!(
            "kind={} version={}",
            before.kind.as_str(),
            before.version.value()
        ),
        format!(
            "deleted version={} revoked={revoked}",
            after.version.value()
        ),
    )
}

/// The committed audit record of the deletion of the role `id`, with the summaries of the role
/// before it and after it.
pub(crate) fn role_audit(
    ids: &dyn UuidGenerator,
    id: RoleId,
    summaries: (String, String),
    stamp: &RoleStamp,
    idempotency_key: Option<&iam_domain::IdempotencyKey>,
) -> Result<SecurityAuditEvent, IamError> {
    let (held, ended) = summaries;
    let parts = SecurityAuditEventParts {
        id: SecurityAuditEventId::from_uuid(ids.generate()),
        occurred_at: stamp.occurred_at,
        actor: stamp.actor.clone(),
        caller_service: None,
        action: AuditAction::new(AUDIT_ACTION)?,
        target: AuditTarget::new("role", &id.to_string())?,
        scope: None,
        before: Some(AuditSummary::new(&held)?),
        after: Some(AuditSummary::new(&ended)?),
        idempotency_key: idempotency_key.cloned(),
        outcome: AuditOutcome::Committed,
        reason: None,
        policy_version: None,
        request_id: None,
    };
    Ok(SecurityAuditEvent::record(parts)?)
}

/// The committed audit record of one assignment that the deletion revoked: the assignment before
/// it, and the version it ended at.
fn revoke_audit(
    ids: &dyn UuidGenerator,
    before: &UserRoleParts,
    after: &UserRoleParts,
    stamp: &UserRoleStamp,
) -> Result<SecurityAuditEvent, IamError> {
    let held = format!(
        "subject={} role={} scope={} version={}",
        before.subject,
        before.role_id,
        before.scope,
        before.version.value()
    );
    let ended = format!(
        "revoked version={} cause={}",
        after.version.value(),
        RevocationCause::RoleDeleted.as_str()
    );
    let parts = SecurityAuditEventParts {
        id: SecurityAuditEventId::from_uuid(ids.generate()),
        occurred_at: stamp.occurred_at,
        actor: stamp.actor.clone(),
        caller_service: None,
        action: AuditAction::new(REVOKE_AUDIT_ACTION)?,
        target: AuditTarget::new("user_role", &after.id.to_string())?,
        scope: Some(after.scope),
        before: Some(AuditSummary::new(&held)?),
        after: Some(AuditSummary::new(&ended)?),
        idempotency_key: None,
        outcome: AuditOutcome::Committed,
        reason: None,
        policy_version: None,
        request_id: None,
    };
    Ok(SecurityAuditEvent::record(parts)?)
}
