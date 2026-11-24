//! Creates a rate policy (FR-64).

use std::sync::Arc;

use iam_domain::{
    ActorRef, ChangeId, ChangeStatement, DecisionEffect, EntityVersion, IamChange, IamChangeParts,
    IamUnitOfWork, IdempotencyRequest, RatePolicy, RatePolicyId, RatePolicyStamp,
    RatePolicyStatement,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use super::gateway_audit::{ChangeRecord, committed};
use crate::error::IamError;
use crate::rate_policy_values::{RatePolicyValues, summary_of};

/// The audit action of a created rate policy.
const AUDIT_ACTION: &str = "rate_policy.create";

/// The kind of the target of the audit record.
const AUDIT_KIND: &str = "rate_policy";

/// Creates a rate policy with the values, as `actor`.
///
/// The caller chooses the identifiers of the rate policy and of the change, so that it can read
/// the receipt and the rate policy after the command returned; the command returns no data.
#[derive(Debug, Clone)]
pub struct CreateRatePolicyCommand {
    /// The identifier of the change, the key of its receipt.
    pub change_id: ChangeId,
    /// The identifier of the new rate policy.
    pub rate_policy_id: RatePolicyId,
    /// Who creates the rate policy.
    pub actor: ActorRef,
    /// The values of the rate policy.
    pub values: RatePolicyValues,
    /// The idempotency key and request digest of the write, when it carries a key.
    pub idempotency: Option<IdempotencyRequest>,
}

impl Command for CreateRatePolicyCommand {
    type Error = IamError;
    const NAME: &'static str = "CreateRatePolicyCommand";
}

/// Handles [`CreateRatePolicyCommand`].
///
/// It validates the values, builds the rate policy and commits its insert, its
/// `iam.rate_policy.created` event and its audit record through the unit of work in one
/// transaction. The rate policy is policy state (`ratepolicy/<id>`), so the change takes the next
/// policy version.
#[derive(Debug)]
pub struct CreateRatePolicyCommandHandler {
    unit_of_work: Arc<dyn IamUnitOfWork>,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl CreateRatePolicyCommandHandler {
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

    async fn create(&self, command: CreateRatePolicyCommand) -> Result<(), IamError> {
        let change = self.change_of(command)?;
        self.unit_of_work
            .commit(change, iam_domain::WriteMode::Published)
            .await?;
        Ok(())
    }

    /// The change that creates the rate policy: the insert, the event and the audit record.
    fn change_of(&self, command: CreateRatePolicyCommand) -> Result<IamChange, IamError> {
        let CreateRatePolicyCommand {
            change_id,
            rate_policy_id,
            actor,
            values,
            idempotency,
        } = command;
        let now = self.clock.now();
        let fields = values.into_fields()?;
        let stamp = RatePolicyStamp {
            event_id: self.uuid_generator.generate(),
            actor: actor.clone(),
            occurred_at: now,
        };
        let mut policy = RatePolicy::create(rate_policy_id, fields, stamp);
        let events = policy.pull_envelopes()?;
        let record = ChangeRecord {
            action: AUDIT_ACTION,
            kind: AUDIT_KIND,
            target_id: rate_policy_id.to_string(),
            actor: &actor,
            occurred_at: now,
            before: None,
            after: summary_of(policy.parts()),
            idempotency: idempotency.as_ref(),
        };
        let audit = committed(self.uuid_generator.as_ref(), record)?;
        let statement = RatePolicyStatement::insert(&policy);
        Ok(IamChange::new(IamChangeParts {
            change_id,
            effect: DecisionEffect::Affected,
            statements: vec![ChangeStatement::from(statement)],
            events,
            audit,
            entity_version: EntityVersion::INITIAL,
            idempotency,
        })?)
    }
}

#[async_trait::async_trait]
impl CommandHandler<CreateRatePolicyCommand> for CreateRatePolicyCommandHandler {
    async fn handle(&self, command: CreateRatePolicyCommand) -> Result<(), IamError> {
        self.create(command).await
    }
}

#[cfg(test)]
mod tests;
