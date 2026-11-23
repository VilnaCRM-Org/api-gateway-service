//! Loads an `OpenAPI` specification version as a draft (FR-1, FR-34).

use std::sync::Arc;

use iam_domain::{
    ActorRef, AuditAction, AuditOutcome, AuditSummary, AuditTarget, ChangeId, ChangeStatement,
    DecisionEffect, EntityVersion, IamChange, IamChangeParts, IamUnitOfWork, OpenApiDocumentParser,
    OpenApiSpec, OpenApiSpecContent, OpenApiSpecParts, OpenApiSpecStatement, RequestDigester,
    SecurityAuditEvent, SecurityAuditEventId, SecurityAuditEventParts, SpecId, SpecStamp,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use super::load_graphql_spec::{content_hash_of, loadable_service};
use crate::error::IamError;

/// The audit action of a loaded version.
const AUDIT_ACTION: &str = "openapi_spec.load";

/// Loads the document of a service as a new draft version, as `actor`.
///
/// The caller chooses the identifiers of the version and of the change, so that it can read the
/// version after the command returned; the command returns no data. The caller sends no document
/// that an earlier version of the service already holds: it finds that version by its hash first.
#[derive(Debug, Clone)]
pub struct LoadOpenApiSpecCommand {
    /// The identifier of the change.
    pub change_id: ChangeId,
    /// The identifier of the new version.
    pub spec_id: SpecId,
    /// Who loads the version.
    pub actor: ActorRef,
    /// The name of the service the document belongs to.
    pub service: String,
    /// The `OpenAPI` JSON document.
    pub document: String,
}

impl Command for LoadOpenApiSpecCommand {
    type Error = IamError;
    const NAME: &'static str = "LoadOpenApiSpecCommand";
}

/// Handles [`LoadOpenApiSpecCommand`].
///
/// It validates the service, parses the document and commits the insert of the draft, its
/// `iam.openapi_spec.loaded` event and its audit record through the unit of work in one
/// transaction. A draft does not affect any decision, so the change takes no policy version.
#[derive(Debug)]
pub struct LoadOpenApiSpecCommandHandler {
    unit_of_work: Arc<dyn IamUnitOfWork>,
    parser: Arc<dyn OpenApiDocumentParser>,
    digester: Arc<dyn RequestDigester>,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl LoadOpenApiSpecCommandHandler {
    /// A handler over the unit of work, the document parser, the digester, the clock and the
    /// identifier source.
    #[must_use]
    pub const fn new(
        unit_of_work: Arc<dyn IamUnitOfWork>,
        parser: Arc<dyn OpenApiDocumentParser>,
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

    async fn load(&self, command: LoadOpenApiSpecCommand) -> Result<(), IamError> {
        let change = self.change_of(command)?;
        self.unit_of_work.commit(change).await?;
        Ok(())
    }

    /// The change that loads the version: the insert, the event and the audit record.
    fn change_of(&self, command: LoadOpenApiSpecCommand) -> Result<IamChange, IamError> {
        let LoadOpenApiSpecCommand {
            change_id,
            spec_id,
            actor,
            service,
            document,
        } = command;
        let service = loadable_service(&service, &actor)?;
        let content_hash = content_hash_of(self.digester.as_ref(), &document);
        let operations = self.parser.parse(&document)?;
        let now = self.clock.now();
        let content = OpenApiSpecContent {
            service,
            content_hash,
            operations,
        };
        let stamp = SpecStamp {
            event_id: self.uuid_generator.generate(),
            actor: actor.clone(),
            occurred_at: now,
        };
        let mut spec = OpenApiSpec::load(spec_id, content, stamp);
        let events = spec.pull_envelopes()?;
        let audit = self.audit(spec.parts(), &actor, now)?;
        let statement = OpenApiSpecStatement::insert(&spec, document);
        Ok(IamChange::new(IamChangeParts {
            change_id,
            effect: DecisionEffect::Unaffected,
            statements: vec![ChangeStatement::SaveOpenApiSpec(Box::new(statement))],
            events,
            audit,
            entity_version: EntityVersion::INITIAL,
            idempotency: None,
        })?)
    }

    /// The committed audit record of the load.
    fn audit(
        &self,
        spec: &OpenApiSpecParts,
        actor: &ActorRef,
        now: std::time::SystemTime,
    ) -> Result<SecurityAuditEvent, IamError> {
        let content = &spec.content;
        let after = format!(
            "service={} hash={} status=draft operations={}",
            content.service,
            content.content_hash,
            content.operations.len()
        );
        let parts = SecurityAuditEventParts {
            id: SecurityAuditEventId::from_uuid(self.uuid_generator.generate()),
            occurred_at: now,
            actor: actor.clone(),
            caller_service: None,
            action: AuditAction::new(AUDIT_ACTION)?,
            target: AuditTarget::new("openapi_spec", &spec.id.to_string())?,
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
impl CommandHandler<LoadOpenApiSpecCommand> for LoadOpenApiSpecCommandHandler {
    async fn handle(&self, command: LoadOpenApiSpecCommand) -> Result<(), IamError> {
        self.load(command).await
    }
}

#[cfg(test)]
mod tests;
