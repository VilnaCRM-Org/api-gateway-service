//! Creates a route of the gateway configuration (FR-57).

use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, AnonymousRouteGuard, ChangeId, DecisionEffect, EntityVersion, GuardCheck, IamChange,
    IamChangeParts, IdempotencyRequest, Route, RouteDraft, RouteFields, RouteId, RouteStamp,
    RouteStatement, WriteMode,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use super::gateway_audit::{ChangeRecord, SystemEntryRefusal, committed};
use super::route_checks::{RoutePorts, summary_of};
use crate::error::IamError;

/// The audited action of a created route.
const AUDIT_ACTION: &str = "route.create";

/// The kind of the audited entry.
pub(super) const AUDIT_KIND: &str = "route";

/// Creates the route `route_id` of `draft` as `actor`.
///
/// The caller chooses the identifiers of the route and of the change, so that it can read the
/// receipt and the route after the command returned; the command returns no data.
#[derive(Debug, Clone)]
pub struct CreateRouteCommand {
    /// The identifier of the change, the key of its receipt.
    pub change_id: ChangeId,
    /// The identifier of the new route.
    pub route_id: RouteId,
    /// Who creates the route.
    pub actor: ActorRef,
    /// The configuration of the route.
    pub draft: RouteDraft,
    /// The idempotency key and request digest of the write, when it carries a key.
    pub idempotency: Option<IdempotencyRequest>,
}

impl Command for CreateRouteCommand {
    type Error = IamError;
    const NAME: &'static str = "CreateRouteCommand";
}

/// Handles [`CreateRouteCommand`].
///
/// It validates the fields, refuses a route of the `iam` service (403 without `iam:route:iam`,
/// 409 `system_entry` with it, both audited as a rejected attempt), checks that the upstream
/// exists and serves the route's service and that the rate policies exist, refuses a route that
/// conflicts with a stored route of its host or whose candidate route table the gateway could not
/// build, and commits the insert, its `iam.route.created` event and its audit record through the
/// unit of work in one transaction; the unit of work writes the `route/<id>` state record and
/// takes the next policy version. The change asks the unit of work to check `RouteScopeGuard` and,
/// for an anonymous or audit-only route, `AnonymousRouteGuard` against the stored policy of the
/// actor.
#[derive(Debug)]
pub struct CreateRouteCommandHandler {
    ports: RoutePorts,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl CreateRouteCommandHandler {
    /// A handler over its ports, the clock and the identifier source.
    #[must_use]
    pub const fn new(
        ports: RoutePorts,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            ports,
            clock,
            uuid_generator,
        }
    }

    async fn create(&self, command: CreateRouteCommand) -> Result<(), IamError> {
        let change = self.change_of(command).await?;
        self.ports
            .unit_of_work
            .commit(change, WriteMode::Published)
            .await?;
        Ok(())
    }

    /// The change that creates the route, after the checks that need the stores.
    async fn change_of(&self, command: CreateRouteCommand) -> Result<IamChange, IamError> {
        let now = self.clock.now();
        let fields = RouteFields::new(&command.draft)?;
        let service = fields.service().clone();
        let refusal = SystemEntryRefusal {
            action: AUDIT_ACTION,
            kind: AUDIT_KIND,
            target_id: command.route_id.to_string(),
            actor: &command.actor,
            occurred_at: now,
        };
        self.ports.admit_service(&service, refusal).await?;
        self.ports.admit_references(&fields).await?;
        let anonymous_key = AnonymousRouteGuard::needs_key_on_create(&fields);
        let stamp = RouteStamp {
            event_id: self.uuid_generator.generate(),
            actor: command.actor.clone(),
            occurred_at: now,
        };
        let route = Route::create(command.route_id, fields, false, stamp);
        self.ports.admit_table(route.parts()).await?;
        let change = self.record(route, command, now)?;
        Ok(change.with_guard(GuardCheck::Route {
            services: vec![service],
            anonymous_key,
        }))
    }

    /// The change of the checked route: the insert, the event and the audit record.
    fn record(
        &self,
        mut route: Route,
        command: CreateRouteCommand,
        now: SystemTime,
    ) -> Result<IamChange, IamError> {
        let events = route.pull_envelopes()?;
        let record = ChangeRecord {
            action: AUDIT_ACTION,
            kind: AUDIT_KIND,
            target_id: command.route_id.to_string(),
            actor: &command.actor,
            occurred_at: now,
            before: None,
            after: summary_of(route.parts(), ""),
            idempotency: command.idempotency.as_ref(),
        };
        let audit = committed(self.uuid_generator.as_ref(), record)?;
        Ok(IamChange::new(IamChangeParts {
            change_id: command.change_id,
            effect: DecisionEffect::Affected,
            statements: vec![RouteStatement::insert(&route).into()],
            events,
            audit,
            entity_version: EntityVersion::INITIAL,
            idempotency: command.idempotency,
        })?)
    }
}

#[async_trait::async_trait]
impl CommandHandler<CreateRouteCommand> for CreateRouteCommandHandler {
    async fn handle(&self, command: CreateRouteCommand) -> Result<(), IamError> {
        self.create(command).await
    }
}

#[cfg(test)]
mod tests;
