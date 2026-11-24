//! Deletes a route of the gateway configuration (FR-57).

use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, ChangeId, DecisionEffect, EntityVersion, GuardCheck, IamChange, IamChangeParts,
    IamUnitOfWork, IdempotencyRequest, RejectedAttemptLog, RouteId, RouteRepository,
    RouteScopeGuard, RouteStamp, RouteStatement, WriteMode,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use super::create_route::AUDIT_KIND;
use super::gateway_audit::{ChangeRecord, SystemEntryRefusal, committed, refuse_system_entry};
use super::route_checks::summary_of;
use crate::error::IamError;

/// The audited action of a deleted route.
const AUDIT_ACTION: &str = "route.delete";

/// Deletes the route `route_id` as `actor`, when the stored route still holds the version
/// `expected`.
///
/// The caller chooses the identifier of the change, so that it can read the receipt after the
/// command returned; the command returns no data, and a deleted route can no longer be read.
#[derive(Debug, Clone)]
pub struct DeleteRouteCommand {
    /// The identifier of the change, the key of its receipt.
    pub change_id: ChangeId,
    /// The route to delete.
    pub route_id: RouteId,
    /// Who deletes the route.
    pub actor: ActorRef,
    /// The version the caller read (`If-Match` or `expectedVersion`).
    pub expected: EntityVersion,
    /// The idempotency key and request digest of the write, when it carries a key.
    pub idempotency: Option<IdempotencyRequest>,
}

impl Command for DeleteRouteCommand {
    type Error = IamError;
    const NAME: &'static str = "DeleteRouteCommand";
}

/// The ports that a deletion reads and writes.
#[derive(Debug, Clone)]
pub struct DeleteRoutePorts {
    /// The routes.
    pub routes: Arc<dyn RouteRepository>,
    /// Commits the change.
    pub unit_of_work: Arc<dyn IamUnitOfWork>,
    /// The buffer that receives the refusal of a system entry.
    pub rejected_attempts: Arc<dyn RejectedAttemptLog>,
}

/// Handles [`DeleteRouteCommand`].
///
/// It reads the route, refuses a system route and one of the `iam` service (409 `system_entry`,
/// audited as a rejected attempt), lets the aggregate check the version, and commits the deletion
/// (a tombstone state record), its `iam.route.deleted` event and its audit record through the
/// unit of work in one transaction. The change asks the unit of work to check `RouteScopeGuard`
/// for the service of the route.
#[derive(Debug)]
pub struct DeleteRouteCommandHandler {
    ports: DeleteRoutePorts,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl DeleteRouteCommandHandler {
    /// A handler over its ports, the clock and the identifier source.
    #[must_use]
    pub const fn new(
        ports: DeleteRoutePorts,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            ports,
            clock,
            uuid_generator,
        }
    }

    async fn delete(&self, command: DeleteRouteCommand) -> Result<(), IamError> {
        let route = self
            .ports
            .routes
            .find_by_id(command.route_id)
            .await?
            .ok_or(IamError::NotFound)?;
        let change = self.change_of(route, command)?;
        self.ports
            .unit_of_work
            .commit(change, WriteMode::Published)
            .await?;
        Ok(())
    }

    /// The change that deletes the route: the tombstone, the event and the audit record.
    fn change_of(
        &self,
        mut route: iam_domain::Route,
        command: DeleteRouteCommand,
    ) -> Result<IamChange, IamError> {
        let DeleteRouteCommand {
            change_id,
            route_id,
            actor,
            expected,
            idempotency,
        } = command;
        let now = self.clock.now();
        let before = route.parts().clone();
        let service = before.fields.service().clone();
        if RouteScopeGuard::check_changeable(&service, before.system).is_err() {
            return Err(self.refuse(route_id, &actor, now));
        }
        let stamp = RouteStamp {
            event_id: self.uuid_generator.generate(),
            actor: actor.clone(),
            occurred_at: now,
        };
        route.delete(Some(expected), stamp)?;
        let events = route.pull_envelopes()?;
        let record = ChangeRecord {
            action: AUDIT_ACTION,
            kind: AUDIT_KIND,
            target_id: route_id.to_string(),
            actor: &actor,
            occurred_at: now,
            before: Some(summary_of(&before, "")),
            after: summary_of(route.parts(), " deleted=true"),
            idempotency: idempotency.as_ref(),
        };
        let audit = committed(self.uuid_generator.as_ref(), record)?;
        let change = IamChange::new(IamChangeParts {
            change_id,
            effect: DecisionEffect::Affected,
            statements: vec![RouteStatement::update(&route, expected).into()],
            events,
            audit,
            entity_version: route.parts().version,
            idempotency,
        })?;
        Ok(change.with_guard(GuardCheck::Route {
            services: vec![service],
            anonymous_key: false,
        }))
    }

    /// The refusal of a change of a system entry, offered to the buffer of the audit log.
    fn refuse(&self, id: RouteId, actor: &ActorRef, occurred_at: SystemTime) -> IamError {
        refuse_system_entry(
            self.ports.rejected_attempts.as_ref(),
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

#[async_trait::async_trait]
impl CommandHandler<DeleteRouteCommand> for DeleteRouteCommandHandler {
    async fn handle(&self, command: DeleteRouteCommand) -> Result<(), IamError> {
        self.delete(command).await
    }
}

#[cfg(test)]
mod tests;
