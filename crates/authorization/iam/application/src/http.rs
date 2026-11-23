//! REST adapter of the IAM context: the state its handlers read, the router that registers
//! them, the header extractors of the writes and their response headers.

pub mod dto;
pub mod extract;
pub mod graphql_spec;
pub mod handler;
pub mod openapi_document_parser;
pub mod response;
pub mod role;
pub mod user_role;

use std::sync::Arc;

use axum::extract::FromRef;
use iam_domain::RequestDigester;
use shared_domain::{Clock, CommandBus, QueryBus, UuidGenerator};
use utoipa_axum::router::OpenApiRouter;

pub use openapi_document_parser::JsonOpenApiDocumentParser;
use utoipa_axum::routes;

/// What the handlers of the IAM context need: the two buses, the identifier source, the clock and
/// the request digester.
#[derive(Debug, Clone)]
pub struct IamState {
    /// Dispatches the commands.
    pub command_bus: Arc<dyn CommandBus>,
    /// Answers the queries.
    pub query_bus: Arc<dyn QueryBus>,
    /// Chooses the identifier of a new record.
    pub uuid_generator: Arc<dyn UuidGenerator>,
    /// Tells the current time.
    pub clock: Arc<dyn Clock>,
    /// Digests the request of an idempotent write.
    pub request_digester: Arc<dyn RequestDigester>,
}

/// The routes of the IAM context, to be nested under `/api`.
#[must_use]
pub fn router<S>() -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    IamState: FromRef<S>,
{
    OpenApiRouter::new()
        .routes(routes!(handler::resolve))
        .routes(routes!(role::create, role::list))
        .routes(routes!(role::get_one, role::update))
        .merge(user_role_router())
}

/// The routes of the role assignments, merged into [`router`].
fn user_role_router<S>() -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    IamState: FromRef<S>,
{
    OpenApiRouter::new()
        .routes(routes!(user_role::assign, user_role::list))
        .routes(routes!(user_role::get_one))
}

/// The routes that upload specification documents, to be nested under `/api`.
///
/// They are a router of their own because the composition root gives them a larger body limit than
/// every other route.
#[must_use]
pub fn specification_router<S>() -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    IamState: FromRef<S>,
{
    OpenApiRouter::new().routes(routes!(graphql_spec::load))
}

#[cfg(test)]
mod tests;
