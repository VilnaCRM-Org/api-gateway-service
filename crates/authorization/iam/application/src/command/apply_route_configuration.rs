//! Applies a declarative route configuration: replaces the full route set of one host (FR-58).

use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, ChangeId, ChangeStatement, DecisionEffect, EntityVersion, EventEnvelope,
    GatewayPrecondition, GuardCheck, IamChange, IamChangeParts, RouteChangeClass,
    RouteConfigurationApplied, RouteDraft, RouteStatement, WriteMode,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use super::gateway_audit::{ChangeRecord, committed};
use super::route_checks::RoutePorts;
use super::route_configuration_plan::{
    AUDIT_ACTION, AUDIT_KIND, RouteConfigurationPlanner, RouteSetPlan, RouteSetRequest,
};
use crate::error::IamError;

/// Replaces the full route set of the host `host` with `routes` as `actor`, when the stored set
/// still has the version `expected`.
///
/// The caller chooses the identifier of the change, so that it can read the receipt after the
/// command returned; the command returns no data. A set that changes nothing commits nothing.
#[derive(Debug, Clone)]
pub struct ApplyRouteConfigurationCommand {
    /// The identifier of the change, the key of its receipt.
    pub change_id: ChangeId,
    /// The host whose routes the set replaces.
    pub host: String,
    /// The declared routes; the host of a draft is replaced by `host`.
    pub routes: Vec<RouteDraft>,
    /// Who applies the set.
    pub actor: ActorRef,
    /// The version of the stored set that the caller read (`If-Match` or `expectedVersion`).
    pub expected: EntityVersion,
}

impl Command for ApplyRouteConfigurationCommand {
    type Error = IamError;
    const NAME: &'static str = "ApplyRouteConfigurationCommand";
}

/// Handles [`ApplyRouteConfigurationCommand`].
///
/// It validates the whole set (the limit of routes, every route, the stored version, the routes of
/// IAM itself, the entries the routes name, the conflicts of the set and the candidate route
/// table), and commits the creations, updates and deletions, their `iam.route.*` events,
/// `iam.route_configuration.applied` and one audit record through the unit of work in one
/// transaction, that is under one policy version. A set whose diff deletes a route, clears
/// `anonymous` or moves `enforcement` from `audit` to `enforce` is revocation-class. The change
/// asks the unit of work to check `RouteScopeGuard` for every service the set touches and
/// `AnonymousRouteGuard` when it creates an anonymous or audit-only route or changes either flag.
#[derive(Debug)]
pub struct ApplyRouteConfigurationCommandHandler {
    ports: RoutePorts,
    max_routes: usize,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl ApplyRouteConfigurationCommandHandler {
    /// A handler over its ports, the largest set it accepts (`ROUTE_CONFIGURATION_MAX_ROUTES`),
    /// the clock and the identifier source.
    #[must_use]
    pub const fn new(
        ports: RoutePorts,
        max_routes: usize,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            ports,
            max_routes,
            clock,
            uuid_generator,
        }
    }

    async fn apply(&self, command: ApplyRouteConfigurationCommand) -> Result<(), IamError> {
        let now = self.clock.now();
        let planner = RouteConfigurationPlanner::new(
            &self.ports,
            self.max_routes,
            self.uuid_generator.as_ref(),
        );
        let plan = planner
            .plan(RouteSetRequest {
                host: &command.host,
                routes: command.routes,
                expected: command.expected,
                actor: &command.actor,
                occurred_at: now,
            })
            .await?;
        if plan.diff.is_empty() {
            return Ok(());
        }
        let change = self.change_of(plan, command.change_id, &command.actor, now)?;
        self.ports
            .unit_of_work
            .commit(change, WriteMode::Published)
            .await?;
        Ok(())
    }

    /// The change that applies the plan: the statements, the events and the audit record.
    fn change_of(
        &self,
        mut plan: RouteSetPlan,
        change_id: ChangeId,
        actor: &ActorRef,
        now: SystemTime,
    ) -> Result<IamChange, IamError> {
        let resulting = plan.resulting_version();
        let applied = self.applied_event(&plan, change_id, actor, now);
        let (statements, mut events) = writes_of(&mut plan)?;
        events.push(EventEnvelope::of(&applied)?);
        let effect = if plan.diff.class() == RouteChangeClass::Revocation {
            DecisionEffect::RevocationClass
        } else {
            DecisionEffect::Affected
        };
        let record = audit_of(&plan, &applied, resulting, actor, now);
        let audit = committed(self.uuid_generator.as_ref(), record)?;
        let change = IamChange::new(IamChangeParts {
            change_id,
            effect,
            statements,
            events,
            audit,
            entity_version: resulting,
            idempotency: None,
        })?;
        Ok(change.with_guard(GuardCheck::Route {
            services: plan.services,
            anonymous_key: plan.anonymous_key,
        }))
    }

    /// The event that records the application of the set.
    fn applied_event(
        &self,
        plan: &RouteSetPlan,
        change_id: ChangeId,
        actor: &ActorRef,
        now: SystemTime,
    ) -> RouteConfigurationApplied {
        let ids = plan.ids();
        RouteConfigurationApplied {
            event_id: self.uuid_generator.generate(),
            change_id,
            host: plan.host.clone(),
            route_count: u32::try_from(plan.table.len()).unwrap_or(u32::MAX),
            created: ids.created,
            updated: ids.updated,
            deleted: ids.deleted,
            actor: actor.clone(),
            occurred_at: now,
        }
    }
}

/// The statements that write the planned routes and the envelopes of their events.
fn writes_of(
    plan: &mut RouteSetPlan,
) -> Result<(Vec<ChangeStatement>, Vec<EventEnvelope>), IamError> {
    let mut statements = preconditions_of(plan);
    let mut events = Vec::new();
    for planned in &mut plan.routes {
        events.extend(planned.route.pull_envelopes()?);
        statements.push(
            planned
                .expected
                .map_or_else(
                    || RouteStatement::insert(&planned.route),
                    |expected| RouteStatement::update(&planned.route, expected),
                )
                .into(),
        );
    }
    Ok((statements, events))
}

/// The statements that make the unit of work check, under the lock of the policy epoch, what the
/// plan read before it: the stored set of the host still has the version the plan was made
/// against (a route created, changed or deleted since then, by any command, refuses the set as a
/// conflict), and the upstream and the rate policies of every route the set writes are still
/// stored and serve it (a concurrent deletion refuses the set instead of leaving a dangling
/// route).
fn preconditions_of(plan: &RouteSetPlan) -> Vec<ChangeStatement> {
    let mut statements: Vec<ChangeStatement> = vec![
        GatewayPrecondition::RouteSetVersion {
            host: plan.host.clone(),
            version: plan.version,
        }
        .into(),
    ];
    let mut seen: Vec<GatewayPrecondition> = Vec::new();
    for planned in &plan.routes {
        let parts = planned.route.parts();
        if parts.deleted_at.is_some() {
            continue;
        }
        let targets = GatewayPrecondition::RouteTargets {
            upstream_id: parts.fields.upstream_id(),
            service: parts.fields.service().clone(),
            rate_policies: parts.fields.rate_policies().to_vec(),
        };
        if !seen.contains(&targets) {
            statements.push(targets.clone().into());
            seen.push(targets);
        }
    }
    statements
}

/// The audit record of the application: the host, and the routes and the version before and
/// after.
fn audit_of<'a>(
    plan: &RouteSetPlan,
    applied: &RouteConfigurationApplied,
    resulting: EntityVersion,
    actor: &'a ActorRef,
    now: SystemTime,
) -> ChangeRecord<'a> {
    ChangeRecord {
        action: AUDIT_ACTION,
        kind: AUDIT_KIND,
        target_id: plan.host.to_string(),
        actor,
        occurred_at: now,
        before: Some(format!(
            "routes={} version={}",
            plan.stored_count,
            plan.version.value()
        )),
        after: format!(
            "routes={} version={} created={} updated={} deleted={}",
            plan.table.len(),
            resulting.value(),
            applied.created.len(),
            applied.updated.len(),
            applied.deleted.len()
        ),
        idempotency: None,
    }
}

#[async_trait::async_trait]
impl CommandHandler<ApplyRouteConfigurationCommand> for ApplyRouteConfigurationCommandHandler {
    async fn handle(&self, command: ApplyRouteConfigurationCommand) -> Result<(), IamError> {
        self.apply(command).await
    }
}

#[cfg(test)]
mod tests;
