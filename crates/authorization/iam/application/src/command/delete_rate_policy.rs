//! Deletes a rate policy that no route references (FR-64).

use std::sync::Arc;

use iam_domain::{
    ActorRef, ChangeId, ChangeStatement, DecisionEffect, EntityVersion, IamChange, IamChangeParts,
    IamUnitOfWork, IdempotencyRequest, RatePolicy, RatePolicyId, RatePolicyRepository,
    RatePolicyStamp, RatePolicyStatement, ReferencedByRoute, RouteRepository,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use super::gateway_audit::{ChangeRecord, committed};
use crate::error::IamError;
use crate::rate_policy_values::summary_of;

/// The audit action of a deleted rate policy.
const AUDIT_ACTION: &str = "rate_policy.delete";

/// The kind of the target of the audit record.
const AUDIT_KIND: &str = "rate_policy";

/// Deletes the rate policy `rate_policy_id` as `actor`, when the stored policy still holds the
/// version `expected` and no route references it.
///
/// The caller chooses the identifier of the change, so that it can read the receipt after the
/// command returned; the command returns no data.
#[derive(Debug, Clone)]
pub struct DeleteRatePolicyCommand {
    /// The identifier of the change, the key of its receipt.
    pub change_id: ChangeId,
    /// The rate policy to delete.
    pub rate_policy_id: RatePolicyId,
    /// Who deletes the rate policy.
    pub actor: ActorRef,
    /// The version the caller read (`If-Match` or `expectedVersion`).
    pub expected: EntityVersion,
    /// The idempotency key and request digest of the write, when it carries a key.
    pub idempotency: Option<IdempotencyRequest>,
}

impl Command for DeleteRatePolicyCommand {
    type Error = IamError;
    const NAME: &'static str = "DeleteRatePolicyCommand";
}

/// Handles [`DeleteRatePolicyCommand`].
///
/// It reads the rate policy, lets the aggregate check the version and record
/// `iam.rate_policy.deleted`, refuses the deletion as a conflict while a route references the
/// policy, and commits the tombstone, the event and the audit record through the unit of work in
/// one transaction. The change takes the next policy version.
#[derive(Debug)]
pub struct DeleteRatePolicyCommandHandler {
    rate_policies: Arc<dyn RatePolicyRepository>,
    routes: Arc<dyn RouteRepository>,
    unit_of_work: Arc<dyn IamUnitOfWork>,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl DeleteRatePolicyCommandHandler {
    /// A handler over the rate policy and route repositories, the unit of work, the clock and the
    /// identifier source.
    #[must_use]
    pub const fn new(
        rate_policies: Arc<dyn RatePolicyRepository>,
        routes: Arc<dyn RouteRepository>,
        unit_of_work: Arc<dyn IamUnitOfWork>,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            rate_policies,
            routes,
            unit_of_work,
            clock,
            uuid_generator,
        }
    }

    async fn delete(&self, command: DeleteRatePolicyCommand) -> Result<(), IamError> {
        let policy = self
            .rate_policies
            .find_by_id(command.rate_policy_id)
            .await?
            .ok_or(IamError::NotFound)?;
        let change = self.change_of(policy, command).await?;
        self.unit_of_work
            .commit(change, iam_domain::WriteMode::Published)
            .await?;
        Ok(())
    }

    /// The change that deletes the rate policy: the tombstone, the event and the audit record.
    ///
    /// # Errors
    ///
    /// [`IamError::ReferencedByRoute`] (409) while a route references the rate policy.
    async fn change_of(
        &self,
        mut policy: RatePolicy,
        command: DeleteRatePolicyCommand,
    ) -> Result<IamChange, IamError> {
        let DeleteRatePolicyCommand {
            change_id,
            rate_policy_id,
            actor,
            expected,
            idempotency,
        } = command;
        let now = self.clock.now();
        let before = summary_of(policy.parts());
        let stamp = RatePolicyStamp {
            event_id: self.uuid_generator.generate(),
            actor: actor.clone(),
            occurred_at: now,
        };
        policy.delete(Some(expected), stamp)?;
        let references = self.routes.count_by_rate_policy(rate_policy_id).await?;
        ReferencedByRoute::check(references)?;
        let events = policy.pull_envelopes()?;
        let record = ChangeRecord {
            action: AUDIT_ACTION,
            kind: AUDIT_KIND,
            target_id: rate_policy_id.to_string(),
            actor: &actor,
            occurred_at: now,
            before: Some(before),
            after: format!("deleted version={}", policy.parts().version.value()),
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
impl CommandHandler<DeleteRatePolicyCommand> for DeleteRatePolicyCommandHandler {
    async fn handle(&self, command: DeleteRatePolicyCommand) -> Result<(), IamError> {
        self.delete(command).await
    }
}

#[cfg(test)]
mod tests;
