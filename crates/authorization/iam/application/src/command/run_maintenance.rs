//! Runs one pass of the periodic maintenance: purges the orphaned grants that stayed orphaned
//! past their retention, removes expired records and anchors the audit chain (FR-38, FR-43,
//! FR-52).
//!
//! It reconciles no cache: drift detection is the anti-entropy task of Story 7.7, and revocation
//! records are pruned only through the tombstones of Story 13.6.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AnchorStamp, AuditAction, AuditChainHead, AuditOutcome, AuditSummary, AuditTarget,
    ChangeId, ChangeStatement, DecisionEffect, EntityVersion, ExpiredOrphanedGrant, IamChange,
    IamChangeParts, IamUnitOfWork, MAX_PURGED_GRANTS_PER_RUN, MaintenanceStore, PermissionGrantSet,
    RepositoryError, RetentionCutoffs, Role, RoleId, RoleRepository, RoleStamp, RoleStatement,
    SecurityAuditEvent, SecurityAuditEventId, SecurityAuditEventParts, SystemComponent,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use crate::error::IamError;

/// The audit action of one purged orphaned grant.
const AUDIT_ACTION: &str = "role.orphaned_grant.purged";

/// The command that runs one pass of the maintenance: orphaned grants older than
/// `orphaned_grant_retention` are purged, and the records of the fixed windows are removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunMaintenanceCommand {
    /// How long a grant stays orphaned before it is purged (`ORPHANED_GRANT_RETENTION`).
    pub orphaned_grant_retention: Duration,
}

impl Command for RunMaintenanceCommand {
    type Error = IamError;
    const NAME: &'static str = "RunMaintenanceCommand";
}

/// Handles [`RunMaintenanceCommand`].
///
/// It purges the orphaned grants first, one change per role through the unit of work with an audit
/// record for each grant (the role state records follow in the same transaction), then removes
/// the expired idempotency records, change receipts and inbound-event ids, and last publishes the
/// head of the audit chain as `iam.security_audit.anchored` through the outbox, so that the head
/// includes the records of this pass. A role that changed while the pass ran keeps its grants for
/// the next pass.
#[derive(Debug)]
pub struct RunMaintenanceCommandHandler {
    store: Arc<dyn MaintenanceStore>,
    roles: Arc<dyn RoleRepository>,
    unit_of_work: Arc<dyn IamUnitOfWork>,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl RunMaintenanceCommandHandler {
    /// A handler over the maintenance store, the roles it reads, the unit of work, the clock and
    /// the identifier source.
    #[must_use]
    pub const fn new(
        store: Arc<dyn MaintenanceStore>,
        roles: Arc<dyn RoleRepository>,
        unit_of_work: Arc<dyn IamUnitOfWork>,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            store,
            roles,
            unit_of_work,
            clock,
            uuid_generator,
        }
    }

    async fn run(&self, command: RunMaintenanceCommand) -> Result<(), IamError> {
        let now = self.clock.now();
        let cutoffs = RetentionCutoffs::at(now, command.orphaned_grant_retention);
        let purged_grants = self.purge_orphaned_grants(&cutoffs, now).await?;
        let purged = self.store.purge_expired_records(&cutoffs).await?;
        let head = self.anchor(now).await?;
        log_pass(purged_grants, purged.total(), head.seq());
        Ok(())
    }

    /// Publishes the head of the audit chain as it is after the purges of this pass.
    async fn anchor(&self, now: SystemTime) -> Result<AuditChainHead, IamError> {
        let stamp = AnchorStamp {
            event_id: self.uuid_generator.generate(),
            occurred_at: now,
        };
        Ok(self.store.anchor_audit_chain(stamp).await?)
    }

    /// Purges the expired orphaned grants role by role; returns how many it purged.
    async fn purge_orphaned_grants(
        &self,
        cutoffs: &RetentionCutoffs,
        now: SystemTime,
    ) -> Result<usize, IamError> {
        let expired = self
            .store
            .expired_orphaned_grants(cutoffs.orphaned_grants, MAX_PURGED_GRANTS_PER_RUN)
            .await?;
        let mut purged: usize = 0;
        for (role_id, grants) in by_role(expired) {
            purged = purged.saturating_add(self.purge_role(role_id, &grants, now).await?);
        }
        Ok(purged)
    }

    /// Removes the `expired` grants from the role in one change; returns how many it removed. A
    /// role that is deleted, or whose expired grants were removed already, needs no change, and a
    /// role that changed since it was read keeps them for the next pass.
    async fn purge_role(
        &self,
        role_id: RoleId,
        expired: &[ExpiredOrphanedGrant],
        now: SystemTime,
    ) -> Result<usize, IamError> {
        let Some(mut role) = self.roles.find_by_id(role_id).await? else {
            return Ok(0);
        };
        let held: Vec<&ExpiredOrphanedGrant> = expired
            .iter()
            .filter(|orphan| role.parts().grants.contains(&orphan.grant))
            .collect();
        let Some((first, rest)) = held.split_first() else {
            return Ok(0);
        };
        let change = self.change_of(&mut role, (first, rest), now)?;
        match self
            .unit_of_work
            .commit(change, iam_domain::WriteMode::Published)
            .await
        {
            Ok(_receipt) => Ok(held.len()),
            Err(RepositoryError::Conflict) => {
                log_deferred(role_id);
                Ok(0)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// The change that removes `held` from the role: the role statement, `iam.role_permissions.changed`
    /// and one audit record for each grant.
    fn change_of(
        &self,
        role: &mut Role,
        (first, rest): (&ExpiredOrphanedGrant, &[&ExpiredOrphanedGrant]),
        now: SystemTime,
    ) -> Result<IamChange, IamError> {
        let actor = ActorRef::System(SystemComponent::Maintenance);
        let expected = role.parts().version;
        let keep = role
            .parts()
            .grants
            .iter()
            .filter(|grant| {
                first.grant != **grant && !rest.iter().any(|orphan| orphan.grant == **grant)
            })
            .cloned();
        let keep = PermissionGrantSet::new(keep)?;
        let stamp = RoleStamp {
            event_id: self.uuid_generator.generate(),
            actor: actor.clone(),
            occurred_at: now,
        };
        role.replace_permissions(Some(expected), keep, stamp)?;
        let events = role.pull_envelopes()?;
        let version = role.parts().version;
        let role_id = role.parts().id;
        let own = self.audit(role_id, first, version, now)?;
        let related = rest
            .iter()
            .map(|orphan| self.audit(role_id, orphan, version, now))
            .collect::<Result<Vec<_>, IamError>>()?;
        let statement = RoleStatement::update(role, expected, actor);
        let change = IamChange::new(IamChangeParts {
            change_id: ChangeId::from_uuid(self.uuid_generator.generate()),
            effect: DecisionEffect::Affected,
            statements: vec![ChangeStatement::SaveRole(Box::new(statement))],
            events,
            audit: own,
            entity_version: version,
            idempotency: None,
        })?;
        Ok(change.with_related_audits(related)?)
    }

    /// The committed audit record of one purged grant: the grant and when it was orphaned before,
    /// the new version of the role after.
    fn audit(
        &self,
        role_id: RoleId,
        orphan: &ExpiredOrphanedGrant,
        version: EntityVersion,
        now: SystemTime,
    ) -> Result<SecurityAuditEvent, IamError> {
        let orphaned_at = orphan
            .orphaned_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        let parts = SecurityAuditEventParts {
            id: SecurityAuditEventId::from_uuid(self.uuid_generator.generate()),
            occurred_at: now,
            actor: ActorRef::System(SystemComponent::Maintenance),
            caller_service: None,
            action: AuditAction::new(AUDIT_ACTION)?,
            target: AuditTarget::new("role", &role_id.to_string())?,
            scope: None,
            before: Some(AuditSummary::new(&format!(
                "grant={} active=false orphanedAtSeconds={orphaned_at}",
                orphan.grant
            ))?),
            after: Some(AuditSummary::new(&format!(
                "purged=true version={}",
                version.value()
            ))?),
            idempotency_key: None,
            outcome: AuditOutcome::Committed,
            reason: None,
            policy_version: None,
            request_id: None,
        };
        Ok(SecurityAuditEvent::record(parts)?)
    }
}

/// The expired grants grouped by role, in role order and keeping the order of the grants.
fn by_role(expired: Vec<ExpiredOrphanedGrant>) -> BTreeMap<RoleId, Vec<ExpiredOrphanedGrant>> {
    let mut grouped: BTreeMap<RoleId, Vec<ExpiredOrphanedGrant>> = BTreeMap::new();
    for orphan in expired {
        grouped.entry(orphan.role_id).or_default().push(orphan);
    }
    grouped
}

/// A committed pass is routine, like the batches of the other singleton tasks, so it is logged at
/// debug level and an idle service writes no entry for it.
fn log_pass(purged_grants: usize, purged_records: u64, anchored_seq: i64) {
    tracing::debug!(
        purged_grants,
        purged_records,
        anchored_seq,
        "maintenance pass committed"
    );
}

fn log_deferred(role_id: RoleId) {
    tracing::debug!(%role_id, "role changed during the purge; its orphaned grants wait for the next pass");
}

#[async_trait::async_trait]
impl CommandHandler<RunMaintenanceCommand> for RunMaintenanceCommandHandler {
    async fn handle(&self, command: RunMaintenanceCommand) -> Result<(), IamError> {
        self.run(command).await
    }
}

#[cfg(test)]
mod tests;
