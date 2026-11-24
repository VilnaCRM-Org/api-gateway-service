//! Creates an upstream of the gateway configuration (FR-56).

use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, ChangeId, DecisionEffect, EntityVersion, GuardCheck, IamChange, IamChangeParts,
    IamGatewaySeed, IamUnitOfWork, IdempotencyRequest, RejectedAttemptLog, RouteScopeGuard,
    Upstream, UpstreamFields, UpstreamId, UpstreamSettingsDraft, UpstreamStamp, UpstreamStatement,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use super::gateway_audit::{ChangeRecord, SystemEntryRefusal, committed, refuse_system_entry};
use crate::error::IamError;

/// The audited action of a created upstream.
const AUDIT_ACTION: &str = "upstream.create";

/// The kind of the audited entry.
pub(super) const AUDIT_KIND: &str = "upstream";

/// Creates the upstream `name` with `settings` as `actor`.
///
/// The caller chooses the identifiers of the upstream and of the change, so that it can read the
/// receipt and the upstream after the command returned; the command returns no data.
#[derive(Debug, Clone)]
pub struct CreateUpstreamCommand {
    /// The identifier of the change, the key of its receipt.
    pub change_id: ChangeId,
    /// The identifier of the new upstream.
    pub upstream_id: UpstreamId,
    /// Who creates the upstream.
    pub actor: ActorRef,
    /// The name, which must be unique among the upstreams that are not deleted.
    pub name: String,
    /// The settings of the upstream.
    pub settings: UpstreamSettingsDraft,
    /// The idempotency key and request digest of the write, when it carries a key.
    pub idempotency: Option<IdempotencyRequest>,
}

impl Command for CreateUpstreamCommand {
    type Error = IamError;
    const NAME: &'static str = "CreateUpstreamCommand";
}

/// Handles [`CreateUpstreamCommand`].
///
/// It validates the fields, refuses an upstream of the `iam` service (409 `system_entry`, audited
/// as a rejected attempt) and commits the insert, its `iam.upstream.created` event and its audit
/// record through the unit of work in one transaction; the unit of work writes the
/// `upstream/<name>` state record and takes the next policy version. The change asks the unit of
/// work to check `RouteScopeGuard` against the stored policy of the actor.
#[derive(Debug)]
pub struct CreateUpstreamCommandHandler {
    unit_of_work: Arc<dyn IamUnitOfWork>,
    rejected_attempts: Arc<dyn RejectedAttemptLog>,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
    own_namespace: Option<String>,
}

impl CreateUpstreamCommandHandler {
    /// The namespace IAM itself runs in; an upstream that targets it is refused (422), like one
    /// that targets `kube-system` or `kube-public`.
    #[must_use]
    pub fn with_own_namespace(mut self, namespace: Option<String>) -> Self {
        self.own_namespace = namespace;
        self
    }

    /// A handler over the unit of work, the buffer of refused attempts, the clock and the
    /// identifier source.
    #[must_use]
    pub const fn new(
        unit_of_work: Arc<dyn IamUnitOfWork>,
        rejected_attempts: Arc<dyn RejectedAttemptLog>,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            unit_of_work,
            rejected_attempts,
            clock,
            uuid_generator,
            own_namespace: None,
        }
    }

    async fn create(&self, command: CreateUpstreamCommand) -> Result<(), IamError> {
        let change = self.change_of(command)?;
        self.unit_of_work
            .commit(change, iam_domain::WriteMode::Published)
            .await?;
        Ok(())
    }

    /// The change that creates the upstream: the insert, the event and the audit record.
    fn change_of(&self, command: CreateUpstreamCommand) -> Result<IamChange, IamError> {
        let CreateUpstreamCommand {
            change_id,
            upstream_id,
            actor,
            name,
            settings,
            idempotency,
        } = command;
        let now = self.clock.now();
        let fields = UpstreamFields::new(&name, &settings)?;
        fields
            .settings()
            .check_namespace(self.own_namespace.as_deref())
            .map_err(|violation| IamError::from(vec![violation]))?;
        let service = fields.settings().catalog_service().clone();
        if RouteScopeGuard::check_changeable(&service, false).is_err()
            || IamGatewaySeed::reserves_upstream_name(fields.name().as_str())
        {
            return Err(self.refuse(upstream_id, &actor, now));
        }
        let stamp = self.stamp(&actor, now);
        let mut upstream = Upstream::create(upstream_id, fields, false, stamp);
        let events = upstream.pull_envelopes()?;
        let record = ChangeRecord {
            action: AUDIT_ACTION,
            kind: AUDIT_KIND,
            target_id: upstream_id.to_string(),
            actor: &actor,
            occurred_at: now,
            before: None,
            after: format!("catalogService={service} version=1"),
            idempotency: idempotency.as_ref(),
        };
        let audit = committed(self.uuid_generator.as_ref(), record)?;
        let statement = UpstreamStatement::insert(&upstream);
        let change = IamChange::new(IamChangeParts {
            change_id,
            effect: DecisionEffect::Affected,
            statements: vec![statement.into()],
            events,
            audit,
            entity_version: EntityVersion::INITIAL,
            idempotency,
        })?;
        Ok(change.with_guard(GuardCheck::RouteScope {
            services: vec![service],
        }))
    }

    /// The stamp of the change: a fresh event id, the actor and the time.
    fn stamp(&self, actor: &ActorRef, now: SystemTime) -> UpstreamStamp {
        UpstreamStamp {
            event_id: self.uuid_generator.generate(),
            actor: actor.clone(),
            occurred_at: now,
        }
    }

    /// The refusal of an upstream of the `iam` service, offered to the buffer of the audit log.
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

#[async_trait::async_trait]
impl CommandHandler<CreateUpstreamCommand> for CreateUpstreamCommandHandler {
    async fn handle(&self, command: CreateUpstreamCommand) -> Result<(), IamError> {
        self.create(command).await
    }
}

#[cfg(test)]
mod tests;
