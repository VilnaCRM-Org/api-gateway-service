//! Retires an active GraphQL specification version and confirms the grants it orphans (FR-1,
//! FR-2, FR-38).

use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, ChangeId, GraphQlSpec, IamChange, IamUnitOfWork, IdempotencyRequest,
    PermissionCatalogue, PermissionKeyKind, PolicyVersion, ServiceName, SpecId, SpecStamp,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use super::create_graphql_permissions::ActivationReads;
use super::spec_retirement::{
    Retirement, RetirementChange, StoredEntry, plan_retirement, retirement_change,
};
use crate::error::IamError;

/// The audit action of a retirement.
const AUDIT_ACTION: &str = "graphql_spec.retire";

/// The command that retires the active version `spec_id` as `actor`.
///
/// The caller chooses the identifier of the change, so that it can read the receipt after the
/// command returned; the command returns no data.
#[derive(Debug, Clone)]
pub struct RetireGraphQlSpecCommand {
    /// The identifier of the change, the key of its receipt.
    pub change_id: ChangeId,
    /// Who retires the version.
    pub actor: ActorRef,
    /// The version to retire.
    pub spec_id: SpecId,
    /// Whether the caller accepts that grants become inactive.
    pub confirm_orphans: bool,
    /// The idempotency key and request digest of the write, when it carries a key.
    pub idempotency: Option<IdempotencyRequest>,
}

impl Command for RetireGraphQlSpecCommand {
    type Error = IamError;
    const NAME: &'static str = "RetireGraphQlSpecCommand";
}

/// Handles [`RetireGraphQlSpecCommand`].
///
/// It reads the version, the other active versions of its service, the stored entries and the
/// grants of the service, computes what the retirement does to the catalogue and, when the caller
/// confirmed the grants it orphans, commits the status change, the deactivated entries, the
/// orphaned grants, the events and the audit record through the unit of work in one transaction.
/// The change affects decisions, so it takes the next policy version; it is guarded by the policy
/// version it was decided against. A version that is not active is refused.
#[derive(Debug)]
pub struct RetireGraphQlSpecCommandHandler {
    reads: ActivationReads,
    unit_of_work: Arc<dyn IamUnitOfWork>,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl RetireGraphQlSpecCommandHandler {
    /// A handler over the repositories it reads, the unit of work, the clock and the identifier
    /// source.
    #[must_use]
    pub const fn new(
        reads: ActivationReads,
        unit_of_work: Arc<dyn IamUnitOfWork>,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            reads,
            unit_of_work,
            clock,
            uuid_generator,
        }
    }

    async fn retire(&self, command: RetireGraphQlSpecCommand) -> Result<(), IamError> {
        let mut spec = self
            .reads
            .specs
            .find_by_id(command.spec_id)
            .await?
            .ok_or(IamError::NotFound)?;
        let now = self.clock.now();
        spec.retire(SpecStamp {
            event_id: self.uuid_generator.generate(),
            actor: command.actor.clone(),
            occurred_at: now,
        })
        .map_err(|_refused| IamError::Conflict)?;
        let epoch = self.reads.policy_epochs.current().await?;
        let change = self
            .change_of(command, &mut spec, epoch.version(), now)
            .await?;
        self.unit_of_work
            .commit(change, iam_domain::WriteMode::Published)
            .await?;
        Ok(())
    }

    /// The change that retires the version, decided once the caller confirmed what needs it.
    async fn change_of(
        &self,
        command: RetireGraphQlSpecCommand,
        spec: &mut GraphQlSpec,
        locked: PolicyVersion,
        now: SystemTime,
    ) -> Result<IamChange, IamError> {
        let service = spec.parts().content.service.clone();
        let retirement = self
            .retirement(spec, &service, command.confirm_orphans, now)
            .await?;
        let plan = plan_retirement(retirement)?;
        retirement_change(RetirementChange {
            change_id: command.change_id,
            actor: command.actor,
            locked,
            idempotency: command.idempotency,
            spec_events: spec.pull_envelopes()?,
            plan,
            action: AUDIT_ACTION,
            target_type: "graphql_spec",
            spec_id: command.spec_id,
            service,
            at: now,
            uuid_generator: self.uuid_generator.as_ref(),
        })
    }

    /// What the retirement is decided against.
    async fn retirement(
        &self,
        spec: &GraphQlSpec,
        service: &ServiceName,
        confirm_orphans: bool,
        at: SystemTime,
    ) -> Result<Retirement, IamError> {
        let spec_id = spec.parts().id;
        let active = self.reads.specs.find_active(service).await?;
        let previous = PermissionCatalogue::for_graphql(
            service,
            &active
                .iter()
                .map(GraphQlSpec::coordinates)
                .collect::<Vec<_>>(),
        );
        let next = PermissionCatalogue::for_graphql(
            service,
            &active
                .iter()
                .filter(|other| other.parts().id != spec_id)
                .map(GraphQlSpec::coordinates)
                .collect::<Vec<_>>(),
        );
        let stored = self
            .reads
            .permissions
            .find_by_service(service)
            .await?
            .iter()
            .map(|entry| StoredEntry {
                key: entry.parts().key.clone(),
                flags: entry.parts().flags,
                active: entry.parts().active,
            })
            .collect();
        let grants = self
            .reads
            .roles
            .find_catalogue_grants(service, PermissionKeyKind::Gql)
            .await?;
        Ok(Retirement {
            kind: PermissionKeyKind::Gql,
            spec_id,
            service: service.clone(),
            activated_at: spec.parts().activated_at,
            previous,
            next,
            stored,
            grants,
            confirm_orphans,
            at,
        })
    }
}

#[async_trait::async_trait]
impl CommandHandler<RetireGraphQlSpecCommand> for RetireGraphQlSpecCommandHandler {
    async fn handle(&self, command: RetireGraphQlSpecCommand) -> Result<(), IamError> {
        self.retire(command).await
    }
}

#[cfg(test)]
mod tests;
