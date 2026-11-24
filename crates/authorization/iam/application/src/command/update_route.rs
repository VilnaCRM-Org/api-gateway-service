//! Changes the configuration of a route (FR-57).

use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, AnonymousRouteGuard, ChangeId, CorsDraft, CorsPolicy, DecisionEffect,
    EnforcementMode, EntityVersion, GuardCheck, HttpMethod, IamChange, IamChangeParts,
    IdempotencyRequest, RatePolicyId, RetryPolicy, Route, RouteDraft, RouteFields, RouteFlag,
    RouteId, RouteParts, RouteScopeGuard, RouteStamp, RouteStatement, UpstreamId, WriteMode,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use super::create_route::AUDIT_KIND;
use super::gateway_audit::{ChangeRecord, SystemEntryRefusal, committed, refuse_system_entry};
use super::route_checks::{RoutePorts, hosts_of, services_of, summary_of, with_preconditions};
use crate::error::IamError;

/// The audited action of an updated route.
const AUDIT_ACTION: &str = "route.update";

/// What an update does with the CORS policy of a route.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CorsChange {
    /// The stored policy stays.
    #[default]
    Keep,
    /// The route has no policy afterwards.
    Remove,
    /// The policy is replaced.
    Set(CorsDraft),
}

/// The members of a route that an update changes; a member that is none keeps the stored value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutePatch {
    /// The host.
    pub host: Option<String>,
    /// The methods the route serves.
    pub methods: Option<Vec<HttpMethod>>,
    /// The path pattern.
    pub path_pattern: Option<String>,
    /// The catalogue service of the route.
    pub service: Option<String>,
    /// The upstream the route forwards to.
    pub upstream_id: Option<UpstreamId>,
    /// Whether the route serves GraphQL.
    pub graphql: Option<bool>,
    /// Whether the route streams its response.
    pub streaming: Option<bool>,
    /// Whether the route is served without authentication.
    pub anonymous: Option<bool>,
    /// The enforcement mode.
    pub enforcement: Option<EnforcementMode>,
    /// The largest request body, in bytes.
    pub body_limit: Option<i64>,
    /// The request timeout, in milliseconds.
    pub request_timeout_ms: Option<i64>,
    /// The idle timeout, in milliseconds.
    pub idle_timeout_ms: Option<i64>,
    /// Which failed requests are retried.
    pub retry: Option<RetryPolicy>,
    /// The rate policies, in the order they apply.
    pub rate_policies: Option<Vec<RatePolicyId>>,
    /// What happens to the CORS policy.
    pub cors: CorsChange,
}

impl RoutePatch {
    /// The draft that results from applying the patch to the stored state.
    fn applied(self, stored: &RouteParts) -> RouteDraft {
        let fields = &stored.fields;
        let flags = fields.flags();
        let flags = [
            (RouteFlag::Graphql, self.graphql),
            (RouteFlag::Streaming, self.streaming),
            (RouteFlag::Anonymous, self.anonymous),
        ]
        .into_iter()
        .fold(flags, |flags, (flag, value)| {
            flags.with(flag, value.unwrap_or_else(|| flags.has(flag)))
        });
        RouteDraft {
            host: self.host.unwrap_or_else(|| fields.host().to_string()),
            methods: self.methods.unwrap_or_else(|| fields.methods().to_vec()),
            path_pattern: self
                .path_pattern
                .unwrap_or_else(|| fields.path_pattern().to_string()),
            service: self.service.unwrap_or_else(|| fields.service().to_string()),
            upstream_id: self.upstream_id.unwrap_or_else(|| fields.upstream_id()),
            flags,
            enforcement: self.enforcement.unwrap_or_else(|| fields.enforcement()),
            body_limit: self
                .body_limit
                .unwrap_or_else(|| i64::try_from(fields.body_limit().bytes()).unwrap_or(i64::MAX)),
            request_timeout_ms: self
                .request_timeout_ms
                .unwrap_or_else(|| i64::from(fields.timeouts().request_ms())),
            idle_timeout_ms: self
                .idle_timeout_ms
                .unwrap_or_else(|| i64::from(fields.timeouts().idle_ms())),
            retry: self.retry.unwrap_or_else(|| fields.retry()),
            rate_policies: self
                .rate_policies
                .unwrap_or_else(|| fields.rate_policies().to_vec()),
            cors: match self.cors {
                CorsChange::Keep => fields.cors().map(cors_draft),
                CorsChange::Remove => None,
                CorsChange::Set(cors) => Some(cors),
            },
        }
    }
}

/// The draft of a stored CORS policy.
fn cors_draft(policy: &CorsPolicy) -> CorsDraft {
    CorsDraft {
        origins: policy.origins().to_vec(),
        methods: policy.methods().to_vec(),
        headers: policy.headers().to_vec(),
        allow_credentials: policy.allow_credentials(),
        max_age_seconds: i64::from(policy.max_age_seconds()),
    }
}

/// Changes the configuration of the route `route_id` as `actor`, when the stored route still holds
/// the version `expected`.
///
/// The caller chooses the identifier of the change, so that it can read the receipt and the route
/// after the command returned; the command returns no data.
#[derive(Debug, Clone)]
pub struct UpdateRouteCommand {
    /// The identifier of the change, the key of its receipt.
    pub change_id: ChangeId,
    /// The route to change.
    pub route_id: RouteId,
    /// Who changes the route.
    pub actor: ActorRef,
    /// The version the caller read (`If-Match` or `expectedVersion`).
    pub expected: EntityVersion,
    /// The members to change.
    pub patch: RoutePatch,
    /// The idempotency key and request digest of the write, when it carries a key.
    pub idempotency: Option<IdempotencyRequest>,
}

impl Command for UpdateRouteCommand {
    type Error = IamError;
    const NAME: &'static str = "UpdateRouteCommand";
}

/// Handles [`UpdateRouteCommand`].
///
/// It reads the route, refuses a system route and one of the `iam` service (409 `system_entry`,
/// audited as a rejected attempt), applies the validated patch (the aggregate checks the version),
/// checks the upstream, the rate policies and the candidate route table as a creation does, and
/// commits the update, its `iam.route.updated` event and its audit record through the unit of work
/// in one transaction. The audit record names the old and the new value of `anonymous` and
/// `enforcement`. The change asks the unit of work to check `RouteScopeGuard` for the service
/// before and after the change and, when it changes `anonymous` or `enforcement`,
/// `AnonymousRouteGuard`.
#[derive(Debug)]
pub struct UpdateRouteCommandHandler {
    ports: RoutePorts,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl UpdateRouteCommandHandler {
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

    async fn update(&self, command: UpdateRouteCommand) -> Result<(), IamError> {
        let route = self
            .ports
            .routes
            .find_by_id(command.route_id)
            .await?
            .ok_or(IamError::NotFound)?;
        let change = self.change_of(route, command).await?;
        self.ports
            .unit_of_work
            .commit(change, WriteMode::Published)
            .await?;
        Ok(())
    }

    /// The change that updates the route, after the checks that need the stores.
    async fn change_of(
        &self,
        mut route: Route,
        command: UpdateRouteCommand,
    ) -> Result<IamChange, IamError> {
        let now = self.clock.now();
        let before = route.parts().clone();
        if RouteScopeGuard::check_changeable(before.fields.service(), before.system).is_err() {
            return Err(self.refuse(command.route_id, &command.actor, now));
        }
        let fields = RouteFields::new(&command.patch.clone().applied(&before))?;
        let after_service = fields.service().clone();
        let anonymous_key = AnonymousRouteGuard::needs_key_on_update(&before.fields, &fields);
        let stamp = RouteStamp {
            event_id: self.uuid_generator.generate(),
            actor: command.actor.clone(),
            occurred_at: now,
        };
        route.update(Some(command.expected), fields, stamp)?;
        let refusal = SystemEntryRefusal {
            action: AUDIT_ACTION,
            kind: AUDIT_KIND,
            target_id: command.route_id.to_string(),
            actor: &command.actor,
            occurred_at: now,
        };
        self.ports.admit_service(&after_service, refusal).await?;
        let reserved = SystemEntryRefusal {
            action: AUDIT_ACTION,
            kind: AUDIT_KIND,
            target_id: command.route_id.to_string(),
            actor: &command.actor,
            occurred_at: now,
        };
        let hosts = hosts_of(before.fields.host(), route.parts().fields.host());
        self.ports.admit_hosts(&hosts, reserved).await?;
        self.ports.admit_references(&route.parts().fields).await?;
        self.ports.admit_table(route.parts()).await?;
        let services = services_of(before.fields.service(), &after_service);
        let change = self.record(route, &before, command, now)?;
        Ok(change.with_guard(GuardCheck::Route {
            services,
            anonymous_key,
        }))
    }

    /// The change of the checked route: the update, the event and the audit record.
    fn record(
        &self,
        mut route: Route,
        before: &RouteParts,
        command: UpdateRouteCommand,
        now: SystemTime,
    ) -> Result<IamChange, IamError> {
        let events = route.pull_envelopes()?;
        let record = ChangeRecord {
            action: AUDIT_ACTION,
            kind: AUDIT_KIND,
            target_id: command.route_id.to_string(),
            actor: &command.actor,
            occurred_at: now,
            before: Some(summary_of(before, "")),
            after: summary_of(route.parts(), ""),
            idempotency: command.idempotency.as_ref(),
        };
        let audit = committed(self.uuid_generator.as_ref(), record)?;
        Ok(IamChange::new(IamChangeParts {
            change_id: command.change_id,
            effect: DecisionEffect::Affected,
            statements: with_preconditions(
                &route,
                RouteStatement::update(&route, command.expected).into(),
            ),
            events,
            audit,
            entity_version: route.parts().version,
            idempotency: command.idempotency,
        })?)
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
impl CommandHandler<UpdateRouteCommand> for UpdateRouteCommandHandler {
    async fn handle(&self, command: UpdateRouteCommand) -> Result<(), IamError> {
        self.update(command).await
    }
}

#[cfg(test)]
mod tests;
