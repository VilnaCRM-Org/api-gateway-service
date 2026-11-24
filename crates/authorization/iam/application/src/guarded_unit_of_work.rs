//! The unit of work that runs the administrative-rights guards of a change before it commits
//! (FR-24, FR-25, FR-30, FR-34).
//!
//! A change names the check it needs ([`GuardCheck`]); this unit of work reads the actor's policy
//! from the policy store (PostgreSQL, never the snapshot) and decides with `EscalationGuard` or
//! `SpecScopeGuard`. A refusal appends a rejected audit record and answers
//! [`RepositoryError::Forbidden`]. A change that passes commits through the unit of work it wraps
//! with the policy version the decision read added as a guard: the transaction locks the policy
//! version, so a change that a concurrent write made stale is refused as a conflict instead of
//! committing on a decision that no longer holds.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, AuditOutcome, AuditReason, AuditSummary, ChangeReceipt, EscalationDenied,
    EscalationGuard, GrantedKey, GraphQlPermissionRepository, GuardCheck, IamChange, IamUnitOfWork,
    InvalidIamValue, PermissionGrant, PermissionKey, PermissionKeyKind, PolicyReadRepository,
    RepositoryError, RestPermissionRepository, RoleId, RoleRepository, SecurityAuditEvent,
    SecurityAuditEventId, SecurityAuditEventParts, SecurityAuditLog, ServiceName, SpecScopeDenied,
    SpecScopeGuard, SubjectPolicy, SubjectRef, WriteMode,
};
use shared_domain::{Clock, UuidGenerator};

/// The stores that a check reads besides the policy of the actor.
#[derive(Debug, Clone)]
pub struct GuardReads {
    /// The policy of the actor.
    pub policy: Arc<dyn PolicyReadRepository>,
    /// The roles, for the grants of an assigned role.
    pub roles: Arc<dyn RoleRepository>,
    /// The REST catalogue, for the sensitive flag of a key.
    pub rest_permissions: Arc<dyn RestPermissionRepository>,
    /// The GraphQL catalogue, for the sensitive flag of a key.
    pub graphql_permissions: Arc<dyn GraphQlPermissionRepository>,
    /// The audit log that receives the rejected record of a refusal.
    pub audit_log: Arc<dyn SecurityAuditLog>,
}

/// Why a guard refused a change.
#[derive(Debug)]
enum Denied {
    Escalation(EscalationDenied),
    SpecScope(SpecScopeDenied),
}

impl Denied {
    /// The machine-readable reason of the rejected audit record.
    const fn reason(&self) -> &'static str {
        match self {
            Self::Escalation(_) => EscalationDenied::CODE,
            Self::SpecScope(_) => SpecScopeDenied::CODE,
        }
    }

    /// What the actor lacked, for the audit record.
    fn summary(&self) -> String {
        match self {
            Self::Escalation(EscalationDenied::Missing { key }) => format!("missing={key}"),
            Self::Escalation(EscalationDenied::OwnAssignment) => "subject=actor".to_owned(),
            Self::SpecScope(denied) => format!("missing={}", denied.key),
        }
    }
}

/// A unit of work that refuses the changes whose actor lacks the administrative rights they need.
#[derive(Debug)]
pub struct GuardedUnitOfWork {
    inner: Arc<dyn IamUnitOfWork>,
    reads: GuardReads,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl GuardedUnitOfWork {
    /// A unit of work over `inner` that decides with the stores of `reads`.
    #[must_use]
    pub const fn new(
        inner: Arc<dyn IamUnitOfWork>,
        reads: GuardReads,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            inner,
            reads,
            clock,
            uuid_generator,
        }
    }

    async fn guarded_commit(
        &self,
        change: IamChange,
        write_mode: WriteMode,
    ) -> Result<ChangeReceipt, RepositoryError> {
        let Some(check) = change.guard().cloned() else {
            return self.inner.commit(change, write_mode).await;
        };
        let Some(actor) = subject_of(&change.parts().audit.parts().actor) else {
            return self.inner.commit(change, write_mode).await;
        };
        let policy = self.reads.policy.read_subject_policy(&actor).await?;
        let now = self.clock.now();
        if let Some(denied) = self.verdict(&check, &actor, &policy, now).await? {
            self.record_refusal(&change, &denied).await?;
            return Err(RepositoryError::Forbidden);
        }
        let decided = policy.policy_version();
        self.inner
            .commit(change.expecting_policy_version(decided), write_mode)
            .await
    }

    /// The reason the check refuses the change, none when it lets it through.
    async fn verdict(
        &self,
        check: &GuardCheck,
        actor: &SubjectRef,
        policy: &SubjectPolicy,
        now: SystemTime,
    ) -> Result<Option<Denied>, RepositoryError> {
        match check {
            GuardCheck::Spec {
                service,
                flag_downgrade,
            } => Ok(SpecScopeGuard::check(policy, now, service, *flag_downgrade)
                .err()
                .map(Denied::SpecScope)),
            GuardCheck::Grants(grants) => {
                let granted = self.granted(grants).await?;
                Ok(EscalationGuard::check(policy, now, &granted)
                    .err()
                    .map(Denied::Escalation))
            }
            GuardCheck::Assignment { subject, role_id } => {
                if let Err(denied) = EscalationGuard::check_subject(actor, subject) {
                    return Ok(Some(Denied::Escalation(denied)));
                }
                let grants = self.role_grants(*role_id).await?;
                let granted = self.granted(&grants).await?;
                Ok(EscalationGuard::check(policy, now, &granted)
                    .err()
                    .map(Denied::Escalation))
            }
        }
    }

    /// The grants of the role; none for a role that is unknown or deleted.
    async fn role_grants(&self, role_id: RoleId) -> Result<Vec<PermissionGrant>, RepositoryError> {
        Ok(self
            .reads
            .roles
            .find_by_id(role_id)
            .await?
            .map(|role| role.parts().grants.iter().cloned().collect())
            .unwrap_or_default())
    }

    /// The grants reduced to what the guard decides on, with the sensitive flag of the catalogue.
    async fn granted(
        &self,
        grants: &[PermissionGrant],
    ) -> Result<Vec<GrantedKey>, RepositoryError> {
        let sensitive = self.sensitive_keys(grants).await?;
        Ok(grants
            .iter()
            .map(|grant| {
                let flagged = matches!(grant, PermissionGrant::Key(key) if sensitive.contains(key));
                GrantedKey::of(grant, flagged)
            })
            .collect())
    }

    /// The exact catalogue keys among the grants whose entry is sensitive.
    async fn sensitive_keys(
        &self,
        grants: &[PermissionGrant],
    ) -> Result<BTreeSet<PermissionKey>, RepositoryError> {
        let mut sensitive = BTreeSet::new();
        for (service, (rest, graphql)) in catalogue_keys(grants) {
            if !rest.is_empty() {
                let entries = self
                    .reads
                    .rest_permissions
                    .find_by_keys(&service, &rest)
                    .await?;
                sensitive.extend(
                    entries
                        .iter()
                        .map(iam_domain::RestPermission::parts)
                        .filter(|parts| parts.flags.is_sensitive())
                        .map(|parts| parts.key.clone()),
                );
            }
            if !graphql.is_empty() {
                let entries = self
                    .reads
                    .graphql_permissions
                    .find_by_keys(&service, &graphql)
                    .await?;
                sensitive.extend(
                    entries
                        .iter()
                        .map(iam_domain::GraphQlPermission::parts)
                        .filter(|parts| parts.flags.is_sensitive())
                        .map(|parts| parts.key.clone()),
                );
            }
        }
        Ok(sensitive)
    }

    /// Appends the rejected record of the refused change to the audit log: the action, the target
    /// and the scope of the change, and the reason of the guard.
    async fn record_refusal(
        &self,
        change: &IamChange,
        denied: &Denied,
    ) -> Result<(), RepositoryError> {
        let record = self.refusal_record(change, denied).map_err(unusable)?;
        self.reads.audit_log.append_batch(&[record]).await?;
        Ok(())
    }

    fn refusal_record(
        &self,
        change: &IamChange,
        denied: &Denied,
    ) -> Result<SecurityAuditEvent, InvalidIamValue> {
        let attempted = change.parts().audit.parts();
        SecurityAuditEvent::record(SecurityAuditEventParts {
            id: SecurityAuditEventId::from_uuid(self.uuid_generator.generate()),
            occurred_at: self.clock.now(),
            actor: attempted.actor.clone(),
            caller_service: attempted.caller_service.clone(),
            action: attempted.action.clone(),
            target: attempted.target.clone(),
            scope: attempted.scope,
            before: Some(AuditSummary::new(&denied.summary())?),
            after: None,
            idempotency_key: None,
            outcome: AuditOutcome::Rejected,
            reason: Some(AuditReason::new(denied.reason())?),
            policy_version: None,
            request_id: attempted.request_id.clone(),
        })
    }
}

/// The subject that an actor acts as; an IAM component acts without a check.
fn subject_of(actor: &ActorRef) -> Option<SubjectRef> {
    match actor {
        ActorRef::User(id) => Some(SubjectRef::user(*id)),
        ActorRef::Service(name) => Some(SubjectRef::service(name.clone())),
        ActorRef::System(_) => None,
    }
}

/// The exact catalogue keys of the grants by service: the REST keys, then the GraphQL keys.
fn catalogue_keys(
    grants: &[PermissionGrant],
) -> BTreeMap<ServiceName, (Vec<PermissionKey>, Vec<PermissionKey>)> {
    let mut keys: BTreeMap<ServiceName, (Vec<PermissionKey>, Vec<PermissionKey>)> = BTreeMap::new();
    for grant in grants {
        if let PermissionGrant::Key(key) = grant {
            let entry = keys.entry(key.service().clone()).or_default();
            match key.kind() {
                PermissionKeyKind::Rest => entry.0.push(key.clone()),
                PermissionKeyKind::Gql => entry.1.push(key.clone()),
                PermissionKeyKind::Reserved => {}
            }
        }
    }
    keys
}

/// A value that breaks a domain invariant while the refusal is recorded is unusable data.
fn unusable(error: InvalidIamValue) -> RepositoryError {
    RepositoryError::Unavailable(Box::new(error))
}

#[async_trait::async_trait]
impl IamUnitOfWork for GuardedUnitOfWork {
    async fn commit(
        &self,
        change: IamChange,
        write_mode: WriteMode,
    ) -> Result<ChangeReceipt, RepositoryError> {
        self.guarded_commit(change, write_mode).await
    }
}

#[cfg(test)]
mod tests;
