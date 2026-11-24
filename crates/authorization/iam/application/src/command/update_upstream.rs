//! Changes the settings of an upstream (FR-56).

use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, ChangeId, DecisionEffect, EntityVersion, GuardCheck, IamChange, IamChangeParts,
    IamGatewaySeed, IamUnitOfWork, IdempotencyRequest, RejectedAttemptLog, RouteScopeGuard,
    ServiceName, Upstream, UpstreamFields, UpstreamId, UpstreamParts, UpstreamProtocol,
    UpstreamRepository, UpstreamSettingsDraft, UpstreamStamp, UpstreamStatement,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use super::create_upstream::AUDIT_KIND;
use super::gateway_audit::{ChangeRecord, SystemEntryRefusal, committed, refuse_system_entry};
use crate::error::IamError;

/// The audited action of an updated upstream.
const AUDIT_ACTION: &str = "upstream.update";

/// The members of an upstream that an update changes; a member that is none keeps the stored
/// value. The name cannot change: a name other than the stored one is refused as a violation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpstreamPatch {
    /// The name of the upstream; it must equal the stored name.
    pub name: Option<String>,
    /// The Kubernetes namespace.
    pub namespace: Option<String>,
    /// The Kubernetes Service name.
    pub service_name: Option<String>,
    /// The catalogue service the upstream serves.
    pub catalog_service: Option<String>,
    /// The port.
    pub port: Option<i64>,
    /// The protocol.
    pub protocol: Option<UpstreamProtocol>,
    /// Whether the caller's credentials are forwarded to the upstream.
    pub forward_credentials: Option<bool>,
    /// The connect timeout, in milliseconds.
    pub connect_timeout_ms: Option<i64>,
    /// The response timeout, in milliseconds.
    pub response_timeout_ms: Option<i64>,
    /// The largest number of concurrent requests.
    pub concurrency_limit: Option<i64>,
    /// The retry budget, in percent of the requests.
    pub retry_budget_percent: Option<i64>,
    /// The number of consecutive failures after which an endpoint is ejected.
    pub outlier_threshold: Option<i64>,
}

impl UpstreamPatch {
    /// The name and the settings that result from applying the patch to the stored state.
    fn applied(self, stored: &UpstreamParts) -> (String, UpstreamSettingsDraft) {
        let settings = &stored.settings;
        let name = self.name.unwrap_or_else(|| stored.name.to_string());
        let draft = UpstreamSettingsDraft {
            namespace: self
                .namespace
                .unwrap_or_else(|| settings.namespace().to_owned()),
            service_name: self
                .service_name
                .unwrap_or_else(|| settings.service_name().to_owned()),
            catalog_service: self
                .catalog_service
                .unwrap_or_else(|| settings.catalog_service().to_string()),
            port: self.port.unwrap_or_else(|| i64::from(settings.port())),
            protocol: self.protocol.unwrap_or_else(|| settings.protocol()),
            forward_credentials: self
                .forward_credentials
                .unwrap_or_else(|| settings.forward_credentials()),
            connect_timeout_ms: self
                .connect_timeout_ms
                .unwrap_or_else(|| i64::from(settings.connect_timeout_ms())),
            response_timeout_ms: self
                .response_timeout_ms
                .unwrap_or_else(|| i64::from(settings.response_timeout_ms())),
            concurrency_limit: self
                .concurrency_limit
                .unwrap_or_else(|| i64::from(settings.concurrency_limit())),
            retry_budget_percent: self
                .retry_budget_percent
                .unwrap_or_else(|| i64::from(settings.retry_budget_percent())),
            outlier_threshold: self
                .outlier_threshold
                .unwrap_or_else(|| i64::from(settings.outlier_threshold())),
        };
        (name, draft)
    }
}

/// Changes the settings of the upstream `upstream_id` as `actor`, when the stored upstream still
/// holds the version `expected`.
///
/// The caller chooses the identifier of the change, so that it can read the receipt and the
/// upstream after the command returned; the command returns no data.
#[derive(Debug, Clone)]
pub struct UpdateUpstreamCommand {
    /// The identifier of the change, the key of its receipt.
    pub change_id: ChangeId,
    /// The upstream to change.
    pub upstream_id: UpstreamId,
    /// Who changes the upstream.
    pub actor: ActorRef,
    /// The version the caller read (`If-Match` or `expectedVersion`).
    pub expected: EntityVersion,
    /// The members to change.
    pub patch: UpstreamPatch,
    /// The idempotency key and request digest of the write, when it carries a key.
    pub idempotency: Option<IdempotencyRequest>,
}

impl Command for UpdateUpstreamCommand {
    type Error = IamError;
    const NAME: &'static str = "UpdateUpstreamCommand";
}

/// Handles [`UpdateUpstreamCommand`].
///
/// It reads the upstream, refuses a system upstream and one of the `iam` service (409
/// `system_entry`, audited as a rejected attempt), applies the validated patch (the aggregate
/// checks the version and the name) and commits the update, its `iam.upstream.updated` event and
/// its audit record through the unit of work in one transaction. The change asks the unit of work
/// to check `RouteScopeGuard` for the catalogue service of the upstream before and after the
/// change.
#[derive(Debug)]
pub struct UpdateUpstreamCommandHandler {
    upstreams: Arc<dyn UpstreamRepository>,
    unit_of_work: Arc<dyn IamUnitOfWork>,
    rejected_attempts: Arc<dyn RejectedAttemptLog>,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
    own_namespace: Option<String>,
}

impl UpdateUpstreamCommandHandler {
    /// The namespace IAM itself runs in; an upstream that targets it is refused (422), like one
    /// that targets `kube-system` or `kube-public`.
    #[must_use]
    pub fn with_own_namespace(mut self, namespace: Option<String>) -> Self {
        self.own_namespace = namespace;
        self
    }

    /// A handler over the upstream repository, the unit of work, the buffer of refused attempts,
    /// the clock and the identifier source.
    #[must_use]
    pub const fn new(
        upstreams: Arc<dyn UpstreamRepository>,
        unit_of_work: Arc<dyn IamUnitOfWork>,
        rejected_attempts: Arc<dyn RejectedAttemptLog>,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            upstreams,
            unit_of_work,
            rejected_attempts,
            clock,
            uuid_generator,
            own_namespace: None,
        }
    }

    async fn update(&self, command: UpdateUpstreamCommand) -> Result<(), IamError> {
        let upstream = self
            .upstreams
            .find_by_id(command.upstream_id)
            .await?
            .ok_or(IamError::NotFound)?;
        let change = self.change_of(upstream, command)?;
        self.unit_of_work
            .commit(change, iam_domain::WriteMode::Published)
            .await?;
        Ok(())
    }

    /// The change that updates the upstream: the update, the event and the audit record.
    fn change_of(
        &self,
        mut upstream: Upstream,
        command: UpdateUpstreamCommand,
    ) -> Result<IamChange, IamError> {
        let UpdateUpstreamCommand {
            change_id,
            upstream_id,
            actor,
            expected,
            patch,
            idempotency,
        } = command;
        let now = self.clock.now();
        let before = upstream.parts().clone();
        self.check_changeable(&before, &actor, now)?;
        let (name, draft) = patch.applied(&before);
        let fields = UpstreamFields::new(&name, &draft)?;
        fields
            .settings()
            .check_namespace(self.own_namespace.as_deref())
            .map_err(|violation| IamError::from(vec![violation]))?;
        let after_service = fields.settings().catalog_service().clone();
        if RouteScopeGuard::check_changeable(&after_service, false).is_err() {
            return Err(self.refuse(upstream_id, &actor, now));
        }
        let stamp = self.stamp(&actor, now);
        upstream.update(Some(expected), fields, stamp)?;
        let events = upstream.pull_envelopes()?;
        let after = upstream.parts();
        let record = ChangeRecord {
            action: AUDIT_ACTION,
            kind: AUDIT_KIND,
            target_id: upstream_id.to_string(),
            actor: &actor,
            occurred_at: now,
            before: Some(summary_of(&before)),
            after: after_summary(&before, after),
            idempotency: idempotency.as_ref(),
        };
        let audit = committed(self.uuid_generator.as_ref(), record)?;
        let statement = UpstreamStatement::update(&upstream, expected);
        let services = services_of(before.settings.catalog_service(), after_service);
        let change = IamChange::new(IamChangeParts {
            change_id,
            effect: DecisionEffect::Affected,
            statements: vec![statement.into()],
            events,
            audit,
            entity_version: upstream.parts().version,
            idempotency,
        })?;
        Ok(change.with_guard(GuardCheck::RouteScope { services }))
    }

    /// The stamp of the change: a fresh event id, the actor and the time.
    fn stamp(&self, actor: &ActorRef, now: SystemTime) -> UpstreamStamp {
        UpstreamStamp {
            event_id: self.uuid_generator.generate(),
            actor: actor.clone(),
            occurred_at: now,
        }
    }

    /// Refuses a system upstream and one of the `iam` service.
    fn check_changeable(
        &self,
        stored: &UpstreamParts,
        actor: &ActorRef,
        now: SystemTime,
    ) -> Result<(), IamError> {
        let service = stored.settings.catalog_service();
        if RouteScopeGuard::check_changeable(service, stored.system).is_err()
            || IamGatewaySeed::reserves_upstream_name(stored.name.as_str())
        {
            return Err(self.refuse(stored.id, actor, now));
        }
        Ok(())
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

/// The state of an upstream that its audit record keeps: the catalogue service and the version.
fn summary_of(upstream: &UpstreamParts) -> String {
    format!(
        "catalogService={} version={}",
        upstream.settings.catalog_service(),
        upstream.version.value()
    )
}

/// The state after the update that its audit record keeps: the catalogue service, the version and
/// the names of the settings that the update changed, separated by commas, or `none`.
fn after_summary(before: &UpstreamParts, after: &UpstreamParts) -> String {
    let changed = before.settings.changed_fields(&after.settings);
    let names = if changed.is_empty() {
        "none".to_owned()
    } else {
        changed.join(",")
    };
    format!("{} changed={names}", summary_of(after))
}

/// The catalogue services of the entry before and after the change, each once.
fn services_of(before: &ServiceName, after: ServiceName) -> Vec<ServiceName> {
    if *before == after {
        vec![after]
    } else {
        vec![before.clone(), after]
    }
}

#[async_trait::async_trait]
impl CommandHandler<UpdateUpstreamCommand> for UpdateUpstreamCommandHandler {
    async fn handle(&self, command: UpdateUpstreamCommand) -> Result<(), IamError> {
        self.update(command).await
    }
}

#[cfg(test)]
mod tests;
