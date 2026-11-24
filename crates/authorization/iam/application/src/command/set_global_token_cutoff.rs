//! Sets the global token cut-off, for an emergency key compromise (FR-1, FR-17, FR-70).

use std::sync::Arc;

use iam_domain::{
    ActorRef, ChangeId, ChangeStatement, DecisionEffect, EntityVersion, EventEnvelope,
    GlobalTokenCutoff, GlobalTokensCutOff, IamChange, IamChangeParts, IamUnitOfWork,
    IdempotencyRequest, InvalidIamValue, PrunePolicy, RevocationStatement, WriteMode,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use super::gateway_audit::{ChangeRecord, committed};
use crate::error::IamError;

/// The audit action of the global cut-off.
const AUDIT_ACTION: &str = "global_tokens.cut_off";

/// The kind of the audit target.
const AUDIT_KIND: &str = "global_cutoff";

/// The identifier of the audit target: there is one global cut-off.
const AUDIT_TARGET: &str = "current";

/// Sets the global cut-off as `actor`: every token issued before the commit time plus the
/// 2-second margin is refused.
///
/// The caller chooses the identifier of the change, so that it can read the receipt after the
/// command returned; the command returns no data.
#[derive(Debug, Clone)]
pub struct SetGlobalTokenCutoffCommand {
    /// The identifier of the change, the key of its receipt.
    pub change_id: ChangeId,
    /// Who sets the cut-off.
    pub actor: ActorRef,
    /// The idempotency key and request digest of the write, when it carries a key.
    pub idempotency: Option<IdempotencyRequest>,
}

impl Command for SetGlobalTokenCutoffCommand {
    type Error = IamError;
    const NAME: &'static str = "SetGlobalTokenCutoffCommand";
}

/// Handles [`SetGlobalTokenCutoffCommand`].
///
/// It commits the cut-off row and its `revocation/global` state record, the
/// `iam.global_tokens.cut_off` event and the audit record in one versioned transaction. The
/// change takes access away, so it is revocation-class.
#[derive(Debug)]
pub struct SetGlobalTokenCutoffCommandHandler {
    unit_of_work: Arc<dyn IamUnitOfWork>,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl SetGlobalTokenCutoffCommandHandler {
    /// A handler over the unit of work, the clock and the identifier source.
    #[must_use]
    pub const fn new(
        unit_of_work: Arc<dyn IamUnitOfWork>,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            unit_of_work,
            clock,
            uuid_generator,
        }
    }

    async fn set(&self, command: SetGlobalTokenCutoffCommand) -> Result<(), IamError> {
        let change = self.change_of(command)?;
        self.unit_of_work
            .commit(change, WriteMode::Published)
            .await?;
        Ok(())
    }

    /// The change of the command: the statement, the event and the audit record.
    fn change_of(&self, command: SetGlobalTokenCutoffCommand) -> Result<IamChange, IamError> {
        let SetGlobalTokenCutoffCommand {
            change_id,
            actor,
            idempotency,
        } = command;
        let now = self.clock.now();
        let cutoff_at = PrunePolicy::cutoff_at(now).ok_or(InvalidIamValue::AuditTimestamp)?;
        let statement = RevocationStatement::GlobalCutoff(GlobalTokenCutoff {
            tokens_valid_after: cutoff_at,
            set_by: actor.clone(),
            set_at: now,
        });
        let event = GlobalTokensCutOff {
            event_id: self.uuid_generator.generate(),
            tokens_valid_after: cutoff_at,
            actor: actor.clone(),
            occurred_at: now,
        };
        let events = vec![EventEnvelope::of(&event)?];
        let record = ChangeRecord {
            action: AUDIT_ACTION,
            kind: AUDIT_KIND,
            target_id: AUDIT_TARGET.to_owned(),
            actor: &actor,
            occurred_at: now,
            before: None,
            after: "global cut-off set".to_owned(),
            idempotency: idempotency.as_ref(),
        };
        let audit = committed(self.uuid_generator.as_ref(), record)?;
        Ok(IamChange::new(IamChangeParts {
            change_id,
            effect: DecisionEffect::RevocationClass,
            statements: vec![ChangeStatement::from(statement)],
            events,
            audit,
            entity_version: EntityVersion::INITIAL,
            idempotency,
        })?)
    }
}

#[async_trait::async_trait]
impl CommandHandler<SetGlobalTokenCutoffCommand> for SetGlobalTokenCutoffCommandHandler {
    async fn handle(&self, command: SetGlobalTokenCutoffCommand) -> Result<(), IamError> {
        self.set(command).await
    }
}

#[cfg(test)]
mod tests;
