//! Deletes an upstream of the gateway configuration (FR-56).

use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, ChangeId, DecisionEffect, EntityVersion, GuardCheck, IamChange, IamChangeParts,
    IamUnitOfWork, IdempotencyRequest, ReferencedByRoute, RejectedAttemptLog, RouteRepository,
    RouteScopeGuard, Upstream, UpstreamId, UpstreamParts, UpstreamRepository, UpstreamStamp,
    UpstreamStatement,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use super::create_upstream::AUDIT_KIND;
use super::gateway_audit::{ChangeRecord, SystemEntryRefusal, committed, refuse_system_entry};
use crate::error::IamError;

/// The audited action of a deleted upstream.
const AUDIT_ACTION: &str = "upstream.delete";

/// Deletes the upstream `upstream_id` as `actor`, when the stored upstream still holds the version
/// `expected` and no route references it.
///
/// The caller chooses the identifier of the change, so that it can read the receipt after the
/// command returned; the command returns no data, and a deleted upstream can no longer be read.
#[derive(Debug, Clone)]
pub struct DeleteUpstreamCommand {
    /// The identifier of the change, the key of its receipt.
    pub change_id: ChangeId,
    /// The upstream to delete.
    pub upstream_id: UpstreamId,
    /// Who deletes the upstream.
    pub actor: ActorRef,
    /// The version the caller read (`If-Match` or `expectedVersion`).
    pub expected: EntityVersion,
    /// The idempotency key and request digest of the write, when it carries a key.
    pub idempotency: Option<IdempotencyRequest>,
}

impl Command for DeleteUpstreamCommand {
    type Error = IamError;
    const NAME: &'static str = "DeleteUpstreamCommand";
}

/// Handles [`DeleteUpstreamCommand`].
///
/// It reads the upstream, refuses a system upstream and one of the `iam` service (409
/// `system_entry`, audited as a rejected attempt), lets the aggregate check the version, refuses
/// the deletion with 409 while a route references the upstream, and commits the deletion (a
/// tombstone state record), its `iam.upstream.deleted` event and its audit record through the unit
/// of work in one transaction. The change asks the unit of work to check `RouteScopeGuard` for the
/// catalogue service of the upstream.
#[derive(Debug)]
pub struct DeleteUpstreamCommandHandler {
    upstreams: Arc<dyn UpstreamRepository>,
    routes: Arc<dyn RouteRepository>,
    unit_of_work: Arc<dyn IamUnitOfWork>,
    rejected_attempts: Arc<dyn RejectedAttemptLog>,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

/// The ports that a deletion reads and writes besides the clock and the identifier source.
#[derive(Debug, Clone)]
pub struct DeleteUpstreamPorts {
    /// The upstreams.
    pub upstreams: Arc<dyn UpstreamRepository>,
    /// The routes, to find those that reference the upstream.
    pub routes: Arc<dyn RouteRepository>,
    /// Commits the change.
    pub unit_of_work: Arc<dyn IamUnitOfWork>,
    /// The buffer that receives the refusal of a system entry.
    pub rejected_attempts: Arc<dyn RejectedAttemptLog>,
}

impl DeleteUpstreamCommandHandler {
    /// A handler over its ports, the clock and the identifier source.
    #[must_use]
    pub fn new(
        ports: DeleteUpstreamPorts,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            upstreams: ports.upstreams,
            routes: ports.routes,
            unit_of_work: ports.unit_of_work,
            rejected_attempts: ports.rejected_attempts,
            clock,
            uuid_generator,
        }
    }

    async fn delete(&self, command: DeleteUpstreamCommand) -> Result<(), IamError> {
        let upstream = self
            .upstreams
            .find_by_id(command.upstream_id)
            .await?
            .ok_or(IamError::NotFound)?;
        let references = self.routes.count_by_upstream(command.upstream_id).await?;
        let change = self.change_of(upstream, references, command)?;
        self.unit_of_work
            .commit(change, iam_domain::WriteMode::Published)
            .await?;
        Ok(())
    }

    /// The change that deletes the upstream: the tombstone, the event and the audit record.
    fn change_of(
        &self,
        mut upstream: Upstream,
        references: u64,
        command: DeleteUpstreamCommand,
    ) -> Result<IamChange, IamError> {
        let DeleteUpstreamCommand {
            change_id,
            upstream_id,
            actor,
            expected,
            idempotency,
        } = command;
        let now = self.clock.now();
        let before = upstream.parts().clone();
        let service = before.settings.catalog_service().clone();
        if RouteScopeGuard::check_changeable(&service, before.system).is_err() {
            return Err(self.refuse(upstream_id, &actor, now));
        }
        let stamp = UpstreamStamp {
            event_id: self.uuid_generator.generate(),
            actor: actor.clone(),
            occurred_at: now,
        };
        upstream.delete(Some(expected), stamp)?;
        ReferencedByRoute::check(references)?;
        let events = upstream.pull_envelopes()?;
        let record = ChangeRecord {
            action: AUDIT_ACTION,
            kind: AUDIT_KIND,
            target_id: upstream_id.to_string(),
            actor: &actor,
            occurred_at: now,
            before: Some(summary_of(&before, "")),
            after: summary_of(upstream.parts(), " deleted=true"),
            idempotency: idempotency.as_ref(),
        };
        let audit = committed(self.uuid_generator.as_ref(), record)?;
        let statement = UpstreamStatement::update(&upstream, expected);
        let change = IamChange::new(IamChangeParts {
            change_id,
            effect: DecisionEffect::Affected,
            statements: vec![statement.into()],
            events,
            audit,
            entity_version: upstream.parts().version,
            idempotency,
        })?;
        Ok(change.with_guard(GuardCheck::RouteScope {
            services: vec![service],
        }))
    }

    /// The refusal of a change of a system entry, offered to the buffer of the audit log.
    fn refuse(&self, id: UpstreamId, actor: &ActorRef, occurred_at: SystemTime) -> IamError {
        refuse_system_entry(
            self.rejected_attempts.as_ref(),
            SystemEntryRefusal {
                action: AUDIT_ACTION,
                kind: AUDIT_KIND,
                target_id: id.to_string(),
                actor,
                occurred_at,
            },
        )
    }
}

/// The state of an upstream that its audit record keeps: the catalogue service and the version,
/// then `suffix`.
fn summary_of(upstream: &UpstreamParts, suffix: &str) -> String {
    format!(
        "catalogService={} version={}{suffix}",
        upstream.settings.catalog_service(),
        upstream.version.value()
    )
}

#[async_trait::async_trait]
impl CommandHandler<DeleteUpstreamCommand> for DeleteUpstreamCommandHandler {
    async fn handle(&self, command: DeleteUpstreamCommand) -> Result<(), IamError> {
        self.delete(command).await
    }
}

#[cfg(test)]
mod tests;
