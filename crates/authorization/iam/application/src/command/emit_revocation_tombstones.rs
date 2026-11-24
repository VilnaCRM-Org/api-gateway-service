//! Emits the tombstones of the revocation records whose prune-after instant has passed (FR-79).
//!
//! A gateway pod never prunes revocation state by its own clock: a record leaves the pods only
//! when the tombstone of this command is applied. The global cut-off is never tombstoned.

use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, ChangeId, ChangeStatement, DecisionEffect, EntityVersion, ExpiredRevocation,
    ExpiredRevocationStore, IamChange, IamChangeParts, IamUnitOfWork, MAX_TOMBSTONES_PER_RUN,
    RepositoryError, RevocationStatement, SecurityAuditEvent, SystemComponent, WriteMode,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use super::gateway_audit::{ChangeRecord, committed};
use crate::error::IamError;

/// The audit action of one tombstoned revocation record.
const AUDIT_ACTION: &str = "revocation.tombstoned";

/// The command that tombstones the revocation records that are past their prune-after instant by
/// the controlled clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmitRevocationTombstonesCommand;

impl Command for EmitRevocationTombstonesCommand {
    type Error = IamError;
    const NAME: &'static str = "EmitRevocationTombstonesCommand";
}

/// Handles [`EmitRevocationTombstonesCommand`].
///
/// It reads at most [`MAX_TOMBSTONES_PER_RUN`] expired session revocations and user cut-offs, and
/// commits one change that deletes them, so that each state record becomes a tombstone under the
/// next policy version, with an audit record for each. A record whose cut-off moved since it was
/// read stays, and a change that conflicts waits for the next run.
#[derive(Debug)]
pub struct EmitRevocationTombstonesCommandHandler {
    store: Arc<dyn ExpiredRevocationStore>,
    unit_of_work: Arc<dyn IamUnitOfWork>,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl EmitRevocationTombstonesCommandHandler {
    /// A handler over the store of expired records, the unit of work, the clock and the identifier
    /// source.
    #[must_use]
    pub const fn new(
        store: Arc<dyn ExpiredRevocationStore>,
        unit_of_work: Arc<dyn IamUnitOfWork>,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            store,
            unit_of_work,
            clock,
            uuid_generator,
        }
    }

    async fn emit(&self) -> Result<(), IamError> {
        let now = self.clock.now();
        let expired = self
            .store
            .expired_revocations(now, MAX_TOMBSTONES_PER_RUN)
            .await?;
        let count = expired.len();
        let mut expired = expired.into_iter();
        let Some(first) = expired.next() else {
            return Ok(());
        };
        let change = self.change_of(first, expired.collect(), now)?;
        match self.unit_of_work.commit(change, WriteMode::Published).await {
            Ok(_receipt) => {
                log_committed(count);
                Ok(())
            }
            Err(RepositoryError::Conflict) => {
                log_deferred(count);
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// The change that deletes `first` and `rest`: one prune statement and one audit record for
    /// each, the audit record of the first being the change's own.
    fn change_of(
        &self,
        first: ExpiredRevocation,
        rest: Vec<ExpiredRevocation>,
        now: SystemTime,
    ) -> Result<IamChange, IamError> {
        let own = self.audit(&first, now)?;
        let related = rest
            .iter()
            .map(|record| self.audit(record, now))
            .collect::<Result<Vec<_>, IamError>>()?;
        let statements = std::iter::once(first)
            .chain(rest)
            .map(|target| ChangeStatement::from(RevocationStatement::Prune { target, now }))
            .collect();
        let change = IamChange::new(IamChangeParts {
            change_id: ChangeId::from_uuid(self.uuid_generator.generate()),
            effect: DecisionEffect::Affected,
            statements,
            events: Vec::new(),
            audit: own,
            entity_version: EntityVersion::INITIAL,
            idempotency: None,
        })?;
        Ok(change.with_related_audits(related)?)
    }

    /// The committed audit record of one tombstoned record: the instant it was kept until.
    fn audit(
        &self,
        record: &ExpiredRevocation,
        now: SystemTime,
    ) -> Result<SecurityAuditEvent, IamError> {
        let actor = ActorRef::System(SystemComponent::Maintenance);
        let pruned_after = record
            .prune_after()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        committed(
            self.uuid_generator.as_ref(),
            ChangeRecord {
                action: AUDIT_ACTION,
                kind: record.kind(),
                target_id: record.target_id(),
                actor: &actor,
                occurred_at: now,
                before: Some(format!("pruneAfterSeconds={pruned_after}")),
                after: "tombstoned=true".to_owned(),
                idempotency: None,
            },
        )
    }
}

/// A committed run is routine, so it is logged at debug level.
fn log_committed(count: usize) {
    tracing::debug!(count, "revocation tombstones committed");
}

fn log_deferred(count: usize) {
    tracing::debug!(
        count,
        "the policy changed during the run; the tombstones wait for the next run"
    );
}

#[async_trait::async_trait]
impl CommandHandler<EmitRevocationTombstonesCommand> for EmitRevocationTombstonesCommandHandler {
    async fn handle(&self, _command: EmitRevocationTombstonesCommand) -> Result<(), IamError> {
        self.emit().await
    }
}

#[cfg(test)]
mod tests;
