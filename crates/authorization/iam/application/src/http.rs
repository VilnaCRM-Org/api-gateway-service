//! REST adapter of the IAM context: the state its handlers read, the router that registers
//! them, the header extractors of the writes and their response headers.

pub mod dto;
pub mod extract;
pub mod graphql_activation;
pub mod graphql_permission;
pub mod graphql_spec;
pub mod handler;
pub mod openapi_document_parser;
pub mod openapi_spec;
pub mod response;
pub mod rest_activation;
pub mod rest_permission;
pub mod role;
pub mod role_permission;
pub mod spec_retirement;
pub mod user_role;

use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, FromRef};
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
        .routes(routes!(role::get_one, role::update, role::delete))
        .merge(graphql_permission_router())
        .merge(rest_permission_router())
        .merge(activation_router())
        .merge(user_role_router())
        .merge(role_permission_router())
}

/// The routes that read the GraphQL permission catalogue, merged into [`router`].
fn graphql_permission_router<S>() -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    IamState: FromRef<S>,
{
    OpenApiRouter::new()
        .routes(routes!(graphql_permission::list))
        .routes(routes!(graphql_permission::get_one))
}

/// The routes that read the REST permission catalogue, merged into [`router`].
fn rest_permission_router<S>() -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    IamState: FromRef<S>,
{
    OpenApiRouter::new()
        .routes(routes!(rest_permission::list))
        .routes(routes!(rest_permission::get_one))
}

/// The routes that activate specification versions, merged into [`router`].
fn activation_router<S>() -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    IamState: FromRef<S>,
{
    OpenApiRouter::new()
        .routes(routes!(graphql_activation::create))
        .routes(routes!(rest_activation::create))
        .routes(routes!(spec_retirement::retire_graphql))
        .routes(routes!(spec_retirement::retire_openapi))
}

/// The routes of the grants of a role, merged into [`router`].
fn role_permission_router<S>() -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    IamState: FromRef<S>,
{
    OpenApiRouter::new()
        .routes(routes!(role_permission::list, role_permission::replace))
        .layer(DefaultBodyLimit::max(
            role_permission::ROLE_PERMISSIONS_BODY_LIMIT_BYTES,
        ))
}

/// The routes of the role assignments, merged into [`router`].
fn user_role_router<S>() -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    IamState: FromRef<S>,
{
    OpenApiRouter::new()
        .routes(routes!(user_role::assign, user_role::list))
        .routes(routes!(
            user_role::get_one,
            user_role::update,
            user_role::revoke
        ))
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
    OpenApiRouter::new()
        .routes(routes!(graphql_spec::load, graphql_spec::list))
        .routes(routes!(graphql_spec::get_one))
        .routes(routes!(graphql_spec::get_diff))
        .merge(openapi_specification_router())
}

/// The routes of the `OpenAPI` specifications, merged into [`specification_router`].
fn openapi_specification_router<S>() -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    IamState: FromRef<S>,
{
    OpenApiRouter::new()
        .routes(routes!(openapi_spec::load, openapi_spec::list))
        .routes(routes!(openapi_spec::get_one))
        .routes(routes!(openapi_spec::get_diff))
}

#[cfg(test)]
mod tests;
