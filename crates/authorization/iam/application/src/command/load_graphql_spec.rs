//! Loads a GraphQL specification version as a draft (FR-1, FR-30).

use std::sync::Arc;

use iam_domain::{
    ActorRef, AuditAction, AuditOutcome, AuditSummary, AuditTarget, ChangeId, ChangeStatement,
    ContentHash, DecisionEffect, EntityVersion, GraphQlSchemaParser, GraphQlSpec,
    GraphQlSpecContent, GraphQlSpecParts, GraphQlSpecStatement, IamChange, IamChangeParts,
    IamUnitOfWork, RequestDigester, SecurityAuditEvent, SecurityAuditEventId,
    SecurityAuditEventParts, ServiceName, SpecId, SpecStamp, SystemComponent,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use crate::error::IamError;

/// The audit action of a loaded version.
const AUDIT_ACTION: &str = "graphql_spec.load";

/// Loads the SDL of a service as a new draft version, as `actor`.
///
/// The caller chooses the identifiers of the version and of the change, so that it can read the
/// version after the command returned; the command returns no data. The caller sends no SDL that
/// an earlier version of the service already holds: it finds that version by its hash first.
#[derive(Debug, Clone)]
pub struct LoadGraphQlSpecCommand {
    /// The identifier of the change.
    pub change_id: ChangeId,
    /// The identifier of the new version.
    pub spec_id: SpecId,
    /// Who loads the version.
    pub actor: ActorRef,
    /// The name of the service the schema belongs to.
    pub service: String,
    /// The SDL document.
    pub sdl: String,
}

impl Command for LoadGraphQlSpecCommand {
    type Error = IamError;
    const NAME: &'static str = "LoadGraphQlSpecCommand";
}

/// The service of a specification that `actor` may load.
///
/// The specifications of the reserved service `iam` come from the startup registration only.
///
/// # Errors
///
/// [`IamError::Invalid`] with a violation of `service` for an invalid name and
/// [`IamError::Forbidden`] for `iam` loaded by any actor other than `system:startup`.
pub(crate) fn loadable_service(name: &str, actor: &ActorRef) -> Result<ServiceName, IamError> {
    let service = ServiceName::new(name)
        .map_err(|error| IamError::invalid_property("service", &error.to_string(), "format"))?;
    if service.is_iam() && *actor != ActorRef::System(SystemComponent::Startup) {
        return Err(IamError::Forbidden);
    }
    Ok(service)
}

/// The content hash of an SDL: the SHA-256 digest of its UTF-8 bytes, which the storage checks
/// against its own.
pub(crate) fn content_hash_of(digester: &dyn RequestDigester, sdl: &str) -> ContentHash {
    ContentHash::from(digester.digest(sdl))
}

/// Handles [`LoadGraphQlSpecCommand`].
///
/// It validates the service, parses the SDL and commits the insert of the draft, its
/// `iam.graphql_spec.loaded` event and its audit record through the unit of work in one
/// transaction. A draft does not affect any decision, so the change takes no policy version.
#[derive(Debug)]
pub struct LoadGraphQlSpecCommandHandler {
    unit_of_work: Arc<dyn IamUnitOfWork>,
    parser: Arc<dyn GraphQlSchemaParser>,
    digester: Arc<dyn RequestDigester>,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl LoadGraphQlSpecCommandHandler {
    /// A handler over the unit of work, the SDL parser, the digester, the clock and the identifier
    /// source.
    #[must_use]
    pub const fn new(
        unit_of_work: Arc<dyn IamUnitOfWork>,
        parser: Arc<dyn GraphQlSchemaParser>,
        digester: Arc<dyn RequestDigester>,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            unit_of_work,
            parser,
            digester,
            clock,
            uuid_generator,
        }
    }

    async fn load(&self, command: LoadGraphQlSpecCommand) -> Result<(), IamError> {
        let change = self.change_of(command)?;
        self.unit_of_work.commit(change).await?;
        Ok(())
    }

    /// The change that loads the version: the insert, the event and the audit record.
    fn change_of(&self, command: LoadGraphQlSpecCommand) -> Result<IamChange, IamError> {
        let LoadGraphQlSpecCommand {
            change_id,
            spec_id,
            actor,
            service,
            sdl,
        } = command;
        let service = loadable_service(&service, &actor)?;
        let content_hash = content_hash_of(self.digester.as_ref(), &sdl);
        let type_graph = self.parser.parse(&sdl)?;
        let now = self.clock.now();
        let content = GraphQlSpecContent {
            service,
            content_hash,
            type_graph,
        };
        let stamp = SpecStamp {
            event_id: self.uuid_generator.generate(),
            actor: actor.clone(),
            occurred_at: now,
        };
        let mut spec = GraphQlSpec::load(spec_id, content, stamp);
        let events = spec.pull_envelopes()?;
        let audit = self.audit(spec.parts(), &actor, now)?;
        let statement = GraphQlSpecStatement::insert(&spec, sdl);
        Ok(IamChange::new(IamChangeParts {
            change_id,
            effect: DecisionEffect::Unaffected,
            statements: vec![ChangeStatement::SaveGraphQlSpec(Box::new(statement))],
            events,
            audit,
            entity_version: EntityVersion::INITIAL,
            idempotency: None,
        })?)
    }

    /// The committed audit record of the load.
    fn audit(
        &self,
        spec: &GraphQlSpecParts,
        actor: &ActorRef,
        now: std::time::SystemTime,
    ) -> Result<SecurityAuditEvent, IamError> {
        let content = &spec.content;
        let after = format!(
            "service={} hash={} status=draft coordinates={}",
            content.service,
            content.content_hash,
            content.type_graph.field_count()
        );
        let parts = SecurityAuditEventParts {
            id: SecurityAuditEventId::from_uuid(self.uuid_generator.generate()),
            occurred_at: now,
            actor: actor.clone(),
            caller_service: None,
            action: AuditAction::new(AUDIT_ACTION)?,
            target: AuditTarget::new("graphql_spec", &spec.id.to_string())?,
            scope: None,
            before: None,
            after: Some(AuditSummary::new(&after)?),
            idempotency_key: None,
            outcome: AuditOutcome::Committed,
            reason: None,
            policy_version: None,
            request_id: None,
        };
        Ok(SecurityAuditEvent::record(parts)?)
    }
}

#[async_trait::async_trait]
impl CommandHandler<LoadGraphQlSpecCommand> for LoadGraphQlSpecCommandHandler {
    async fn handle(&self, command: LoadGraphQlSpecCommand) -> Result<(), IamError> {
        self.load(command).await
    }
}

#[cfg(test)]
mod tests;
