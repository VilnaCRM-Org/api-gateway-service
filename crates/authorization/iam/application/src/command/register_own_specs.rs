//! Registers IAM's own specifications in its catalogue at startup (FR-4, FR-45).

use std::sync::Arc;

use iam_domain::{ActorRef, ChangeId, RequestDigester, ServiceName, SpecId, SystemComponent};
use shared_domain::{BusError, Command, CommandBus, CommandHandler, QueryBus, UuidGenerator};

use super::create_graphql_permissions::CreateGraphQlPermissionsCommand;
use super::create_rest_permissions::CreateRestPermissionsCommand;
use super::load_graphql_spec::{LoadGraphQlSpecCommand, content_hash_of};
use super::load_openapi_spec::LoadOpenApiSpecCommand;
use crate::error::IamError;
use crate::query::find_graphql_spec::FindGraphQlSpecQuery;
use crate::query::find_openapi_spec::FindOpenApiSpecQuery;

/// The command that registers the documents of the running build as the specifications of the
/// service `iam`, as `system:startup`.
///
/// The composition root generates the documents: the `OpenAPI` document holds the operations
/// tagged `iam`, and the SDL the GraphQL operations that IAM owns.
#[derive(Debug, Clone)]
pub struct RegisterOwnSpecsCommand {
    /// The `OpenAPI` JSON document of IAM's own REST operations.
    pub openapi_document: String,
    /// The SDL of IAM's own GraphQL operations.
    pub graphql_sdl: String,
}

impl Command for RegisterOwnSpecsCommand {
    type Error = IamError;
    const NAME: &'static str = "RegisterOwnSpecsCommand";
}

/// Handles [`RegisterOwnSpecsCommand`].
///
/// For each document it finds the version of `iam` that holds it by its content hash, loads a draft
/// when there is none and activates the version. The activation is additive: the new version joins
/// the active ones, so the catalogue is their union and no grant is orphaned, and a version that is
/// active already is a no-op, so a second start of the same build creates no version, event or
/// audit record. The caller serializes the instances that start at the same time.
#[derive(Debug)]
pub struct RegisterOwnSpecsCommandHandler {
    command_bus: Arc<dyn CommandBus>,
    query_bus: Arc<dyn QueryBus>,
    digester: Arc<dyn RequestDigester>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

/// The service that the registration writes to.
fn iam() -> ServiceName {
    ServiceName::iam().clone()
}

/// The actor of every change of the registration.
const fn actor() -> ActorRef {
    ActorRef::System(SystemComponent::Startup)
}

/// A bus failure as the error of the registration: the handler's own error, or an internal error
/// for a message that has no handler.
fn failed(error: BusError<IamError>) -> IamError {
    match error {
        BusError::Handler(error) => error,
        BusError::NotRegistered { .. } => IamError::Internal(Box::new(error)),
    }
}

impl RegisterOwnSpecsCommandHandler {
    /// A handler over the buses that reach the handlers of the loads and activations and the
    /// queries that find versions, the digester that hashes the documents and the identifier
    /// source.
    #[must_use]
    pub const fn new(
        command_bus: Arc<dyn CommandBus>,
        query_bus: Arc<dyn QueryBus>,
        digester: Arc<dyn RequestDigester>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            command_bus,
            query_bus,
            digester,
            uuid_generator,
        }
    }

    async fn register(&self, command: RegisterOwnSpecsCommand) -> Result<(), IamError> {
        self.register_rest(command.openapi_document).await?;
        self.register_graphql(command.graphql_sdl).await
    }

    fn spec_id(&self) -> SpecId {
        SpecId::from_uuid(self.uuid_generator.generate())
    }

    fn change_id(&self) -> ChangeId {
        ChangeId::from_uuid(self.uuid_generator.generate())
    }

    /// Finds or loads the `OpenAPI` version of the document and activates it.
    async fn register_rest(&self, document: String) -> Result<(), IamError> {
        let content_hash = content_hash_of(self.digester.as_ref(), &document);
        let existing = self
            .query_bus
            .ask(FindOpenApiSpecQuery {
                service: iam(),
                content_hash,
            })
            .await
            .map_err(failed)?;
        let spec_id = if let Some(spec_id) = existing {
            spec_id
        } else {
            let spec_id = self.spec_id();
            let load = LoadOpenApiSpecCommand {
                change_id: self.change_id(),
                spec_id,
                actor: actor(),
                service: iam().as_str().to_owned(),
                document,
            };
            self.command_bus.dispatch(load).await.map_err(failed)?;
            spec_id
        };
        let activate = CreateRestPermissionsCommand {
            change_id: self.change_id(),
            actor: actor(),
            spec_id,
            renames: Vec::new(),
            confirm_orphans: false,
            confirm_flag_downgrade: true,
            idempotency: None,
        };
        self.command_bus.dispatch(activate).await.map_err(failed)
    }

    /// Finds or loads the GraphQL version of the SDL and activates it.
    async fn register_graphql(&self, sdl: String) -> Result<(), IamError> {
        let content_hash = content_hash_of(self.digester.as_ref(), &sdl);
        let existing = self
            .query_bus
            .ask(FindGraphQlSpecQuery {
                service: iam(),
                content_hash,
            })
            .await
            .map_err(failed)?;
        let spec_id = if let Some(spec_id) = existing {
            spec_id
        } else {
            let spec_id = self.spec_id();
            let load = LoadGraphQlSpecCommand {
                change_id: self.change_id(),
                spec_id,
                actor: actor(),
                service: iam().as_str().to_owned(),
                sdl,
            };
            self.command_bus.dispatch(load).await.map_err(failed)?;
            spec_id
        };
        let activate = CreateGraphQlPermissionsCommand {
            change_id: self.change_id(),
            actor: actor(),
            spec_id,
            renames: Vec::new(),
            confirm_orphans: false,
            confirm_flag_downgrade: true,
            idempotency: None,
        };
        self.command_bus.dispatch(activate).await.map_err(failed)
    }
}

#[async_trait::async_trait]
impl CommandHandler<RegisterOwnSpecsCommand> for RegisterOwnSpecsCommandHandler {
    async fn handle(&self, command: RegisterOwnSpecsCommand) -> Result<(), IamError> {
        self.register(command).await
    }
}

#[cfg(test)]
mod tests;
