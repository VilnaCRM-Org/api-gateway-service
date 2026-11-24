//! Changes the configuration of a rate policy (FR-64).

use std::sync::Arc;

use iam_domain::{
    ActorRef, ChangeId, ChangeStatement, DecisionEffect, EntityVersion, IamChange, IamChangeParts,
    IamUnitOfWork, IdempotencyRequest, RatePolicy, RatePolicyId, RatePolicyRepository,
    RatePolicyStamp, RatePolicyStatement,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use super::gateway_audit::{ChangeRecord, committed};
use crate::error::IamError;
use crate::rate_policy_values::{RatePolicyPatch, summary_of};

/// The audit action of an updated rate policy.
const AUDIT_ACTION: &str = "rate_policy.update";

/// The kind of the target of the audit record.
const AUDIT_KIND: &str = "rate_policy";

/// Changes the rate policy `rate_policy_id` as `actor`, when the stored policy still holds the
/// version `expected`.
///
/// The caller chooses the identifier of the change, so that it can read the receipt and the rate
/// policy after the command returned; the command returns no data.
#[derive(Debug, Clone)]
pub struct UpdateRatePolicyCommand {
    /// The identifier of the change, the key of its receipt.
    pub change_id: ChangeId,
    /// The rate policy to change.
    pub rate_policy_id: RatePolicyId,
    /// Who changes the rate policy.
    pub actor: ActorRef,
    /// The version the caller read (`If-Match` or `expectedVersion`).
    pub expected: EntityVersion,
    /// The members that change.
    pub patch: RatePolicyPatch,
    /// The idempotency key and request digest of the write, when it carries a key.
    pub idempotency: Option<IdempotencyRequest>,
}

impl Command for UpdateRatePolicyCommand {
    type Error = IamError;
    const NAME: &'static str = "UpdateRatePolicyCommand";
}

/// Handles [`UpdateRatePolicyCommand`].
///
/// It reads the rate policy, applies the patch to its configuration, validates the result and lets
/// the aggregate check the version; it commits the update, its `iam.rate_policy.updated` event
/// and its audit record through the unit of work in one transaction and takes the next policy
/// version.
#[derive(Debug)]
pub struct UpdateRatePolicyCommandHandler {
    rate_policies: Arc<dyn RatePolicyRepository>,
    unit_of_work: Arc<dyn IamUnitOfWork>,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl UpdateRatePolicyCommandHandler {
    /// A handler over the rate policy repository, the unit of work, the clock and the identifier
    /// source.
    #[must_use]
    pub const fn new(
        rate_policies: Arc<dyn RatePolicyRepository>,
        unit_of_work: Arc<dyn IamUnitOfWork>,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            rate_policies,
            unit_of_work,
            clock,
            uuid_generator,
        }
    }

    async fn update(&self, command: UpdateRatePolicyCommand) -> Result<(), IamError> {
        let policy = self
            .rate_policies
            .find_by_id(command.rate_policy_id)
            .await?
            .ok_or(IamError::NotFound)?;
        let change = self.change_of(policy, command)?;
        self.unit_of_work
            .commit(change, iam_domain::WriteMode::Published)
            .await?;
        Ok(())
    }

    /// The change that updates the rate policy: the update, the event and the audit record.
    fn change_of(
        &self,
        mut policy: RatePolicy,
        command: UpdateRatePolicyCommand,
    ) -> Result<IamChange, IamError> {
        let UpdateRatePolicyCommand {
            change_id,
            rate_policy_id,
            actor,
            expected,
            patch,
            idempotency,
        } = command;
        let now = self.clock.now();
        let fields = patch.applied_to(&policy.parts().fields).into_fields()?;
        let before = summary_of(policy.parts());
        let stamp = RatePolicyStamp {
            event_id: self.uuid_generator.generate(),
            actor: actor.clone(),
            occurred_at: now,
        };
        policy.update(Some(expected), fields, stamp)?;
        let events = policy.pull_envelopes()?;
        let record = ChangeRecord {
            action: AUDIT_ACTION,
            kind: AUDIT_KIND,
            target_id: rate_policy_id.to_string(),
            actor: &actor,
            occurred_at: now,
            before: Some(before),
            after: summary_of(policy.parts()),
            idempotency: idempotency.as_ref(),
        };
        let audit = committed(self.uuid_generator.as_ref(), record)?;
        let statement = RatePolicyStatement::update(&policy, expected);
        Ok(IamChange::new(IamChangeParts {
            change_id,
            effect: DecisionEffect::Affected,
            statements: vec![ChangeStatement::from(statement)],
            events,
            audit,
            entity_version: policy.parts().version,
            idempotency,
        })?)
    }
}

#[async_trait::async_trait]
impl CommandHandler<UpdateRatePolicyCommand> for UpdateRatePolicyCommandHandler {
    async fn handle(&self, command: UpdateRatePolicyCommand) -> Result<(), IamError> {
        self.update(command).await
    }
}

#[cfg(test)]
mod tests;
