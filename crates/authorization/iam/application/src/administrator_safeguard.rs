//! Keeps at least one active global administrator: the use cases that revoke or shorten an
//! administrator assignment ask it first (FR-5).

use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ADMINISTRATORS_LOCK, ActorRef, AuditAction, AuditOutcome, AuditReason, AuditSummary,
    AuditTarget, LastAdministratorGuard, LastAdministratorRefused, LockGuard, RoleParts,
    RoleRepository, SecurityAuditEvent, SecurityAuditEventId, SecurityAuditEventParts,
    SecurityAuditLog, StartupLock, UserRoleId, UserRolePageQuery, UserRoleParts,
    UserRoleRepository,
};
use shared_domain::{Clock, UuidGenerator};

use crate::error::IamError;

/// The audit action of a refused revocation.
const REVOKE_ACTION: &str = "user_role.revoke";

/// The audit action of a refused change of the expiry.
const UPDATE_ACTION: &str = "user_role.update";

/// The reason that a refusal records.
const REASON: &str = "last_administrator";

/// The number of assignments that one read of the other administrators asks for.
const PAGE: u32 = 100;

/// What a change of an administrator assignment is about to do.
#[derive(Debug, Clone, Copy)]
enum Attempt {
    /// End the assignment.
    Revoke,
    /// Change the expiry to the given instant, or clear it.
    Expire(Option<SystemTime>),
}

impl Attempt {
    const fn action(self) -> &'static str {
        match self {
            Self::Revoke => REVOKE_ACTION,
            Self::Expire(_) => UPDATE_ACTION,
        }
    }

    fn check(
        self,
        guard: LastAdministratorGuard,
        assignment: &UserRoleParts,
        others: usize,
    ) -> Result<(), LastAdministratorRefused> {
        match self {
            Self::Revoke => guard.check_revocation(others),
            Self::Expire(new) => guard.check_expiry(assignment.expires_at, new, others),
        }
    }
}

/// The permission to commit a change of an administrator assignment; it holds the lock that
/// serializes such changes until it is dropped, so two administrators cannot revoke each other at
/// the same time.
#[derive(Debug)]
pub struct Admission {
    _lock: Option<Box<dyn LockGuard>>,
}

/// The ports that the safeguard reads and writes besides the clock and the identifier source.
#[derive(Debug, Clone)]
pub struct SafeguardPorts {
    /// The roles.
    pub roles: Arc<dyn RoleRepository>,
    /// The assignments.
    pub user_roles: Arc<dyn UserRoleRepository>,
    /// The audit log that receives the rejected record of a refusal.
    pub audit_log: Arc<dyn SecurityAuditLog>,
    /// The cross-instance lock that serializes the changes of administrator assignments.
    pub startup_lock: Arc<dyn StartupLock>,
}

/// Decides whether an assignment may be revoked or given an earlier expiry without leaving the
/// platform without an active global administrator, and audits the refusal.
#[derive(Debug)]
pub struct AdministratorSafeguard {
    roles: Arc<dyn RoleRepository>,
    user_roles: Arc<dyn UserRoleRepository>,
    audit_log: Arc<dyn SecurityAuditLog>,
    startup_lock: Arc<dyn StartupLock>,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl AdministratorSafeguard {
    /// A safeguard over its ports, the clock and the identifier source.
    #[must_use]
    pub fn new(
        ports: SafeguardPorts,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            roles: ports.roles,
            user_roles: ports.user_roles,
            audit_log: ports.audit_log,
            startup_lock: ports.startup_lock,
            clock,
            uuid_generator,
        }
    }

    /// The permission to revoke `assignment` as `actor`.
    ///
    /// # Errors
    ///
    /// [`IamError::LastAdministrator`] when it is the last active global administrator assignment
    /// (the refusal is audited as `user_role.revoke` rejected with the reason
    /// `last_administrator`), and [`IamError::Storage`] when the storage fails.
    pub async fn admit_revocation(
        &self,
        assignment: &UserRoleParts,
        actor: &ActorRef,
    ) -> Result<Admission, IamError> {
        self.admit(assignment, actor, Attempt::Revoke).await
    }

    /// The permission to change the expiry of `assignment` to `expires_at` as `actor`.
    ///
    /// # Errors
    ///
    /// [`IamError::LastAdministrator`] when it would end the last active global administrator
    /// assignment earlier (audited as `user_role.update` rejected), and [`IamError::Storage`] when
    /// the storage fails.
    pub async fn admit_expiry(
        &self,
        assignment: &UserRoleParts,
        expires_at: Option<SystemTime>,
        actor: &ActorRef,
    ) -> Result<Admission, IamError> {
        self.admit(assignment, actor, Attempt::Expire(expires_at))
            .await
    }

    async fn admit(
        &self,
        assignment: &UserRoleParts,
        actor: &ActorRef,
        attempt: Attempt,
    ) -> Result<Admission, IamError> {
        let Some(role) = self.roles.find_by_id(assignment.role_id).await? else {
            return Ok(Admission { _lock: None });
        };
        let now = self.clock.now();
        let guard = LastAdministratorGuard::of(role.parts(), assignment, now);
        if !guard.protects() {
            return Ok(Admission { _lock: None });
        }
        let lock = self.startup_lock.acquire(ADMINISTRATORS_LOCK).await?;
        let others = self
            .has_other_administrator(role.parts(), assignment.id, now)
            .await?;
        if attempt
            .check(guard, assignment, usize::from(others))
            .is_err()
        {
            self.record_refusal(assignment, actor, attempt).await?;
            return Err(IamError::LastAdministrator);
        }
        Ok(Admission { _lock: Some(lock) })
    }

    /// Whether an assignment of the role other than `excluded` is active and global at `now`.
    async fn has_other_administrator(
        &self,
        role: &RoleParts,
        excluded: UserRoleId,
        now: SystemTime,
    ) -> Result<bool, IamError> {
        let mut after = None;
        loop {
            let query = UserRolePageQuery {
                limit: PAGE,
                after,
                subject_kind: None,
                subject_id: None,
                role_id: Some(role.id),
                project_id: None,
                include_expired: false,
                now,
            };
            let page = self.user_roles.find_page(&query).await?;
            if page.iter().any(|user_role| {
                LastAdministratorGuard::is_other_administrator(user_role.parts(), excluded, now)
            }) {
                return Ok(true);
            }
            let full = u32::try_from(page.len()).is_ok_and(|length| length >= PAGE);
            match page.last() {
                Some(last) if full => after = Some(last.parts().id),
                _ => return Ok(false),
            }
        }
    }

    /// Appends the rejected record of the refusal to the audit log.
    async fn record_refusal(
        &self,
        assignment: &UserRoleParts,
        actor: &ActorRef,
        attempt: Attempt,
    ) -> Result<(), IamError> {
        let held = format!(
            "subject={} role={} scope={} version={}",
            assignment.subject,
            assignment.role_id,
            assignment.scope,
            assignment.version.value()
        );
        let parts = SecurityAuditEventParts {
            id: SecurityAuditEventId::from_uuid(self.uuid_generator.generate()),
            occurred_at: self.clock.now(),
            actor: actor.clone(),
            caller_service: None,
            action: AuditAction::new(attempt.action())?,
            target: AuditTarget::new("user_role", &assignment.id.to_string())?,
            scope: Some(assignment.scope),
            before: Some(AuditSummary::new(&held)?),
            after: None,
            idempotency_key: None,
            outcome: AuditOutcome::Rejected,
            reason: Some(AuditReason::new(REASON)?),
            policy_version: None,
            request_id: None,
        };
        self.audit_log
            .append_batch(&[SecurityAuditEvent::record(parts)?])
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
