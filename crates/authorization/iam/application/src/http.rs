//! REST adapter of the IAM context: the state its handlers read, the router that registers
//! them, the header extractors of the writes and their response headers.

pub mod access_validation;
pub mod bulk_operation;
pub mod dto;
pub mod extract;
pub mod global_token_cutoff;
pub mod graphql_activation;
pub mod graphql_permission;
pub mod graphql_spec;
pub mod handler;
pub mod openapi_document_parser;
pub mod openapi_spec;
pub mod policy_resync;
pub mod rate_policy;
pub mod response;
pub mod rest_activation;
pub mod rest_permission;
pub mod role;
pub mod role_permission;
pub mod route;
pub mod route_configuration;
pub mod security_audit_event;
pub mod session_revocation;
pub mod spec_retirement;
pub mod upstream;
pub mod user_role;
pub mod user_role_permission;

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
        .merge(access_validation_router())
        .merge(graphql_permission_router())
        .merge(rest_permission_router())
        .merge(activation_router())
        .merge(user_role_router())
        .merge(role_permission_router())
        .merge(user_role_permission_router())
        .merge(rate_policy_router())
        .merge(bulk_operation_router())
        .merge(policy_resync_router())
        .merge(revocation_router())
        .merge(upstream_router())
        .merge(route_router())
        .merge(route_configuration_router())
        .merge(security_audit_event_router())
}

/// The routes of the access validation, single and batch, merged into [`router`].
fn access_validation_router<S>() -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    IamState: FromRef<S>,
{
    OpenApiRouter::new()
        .routes(routes!(access_validation::validate))
        .merge(
            OpenApiRouter::new()
                .routes(routes!(access_validation::validate_batch))
                .layer(DefaultBodyLimit::max(
                    access_validation::ACCESS_VALIDATION_BATCH_BODY_LIMIT_BYTES,
                )),
        )
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

/// The route of the effective permissions of a user, merged into [`router`].
fn user_role_permission_router<S>() -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    IamState: FromRef<S>,
{
    OpenApiRouter::new().routes(routes!(user_role_permission::list))
}

/// The routes that read the bulk operations, merged into [`router`].
fn bulk_operation_router<S>() -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    IamState: FromRef<S>,
{
    OpenApiRouter::new()
        .routes(routes!(bulk_operation::list))
        .routes(routes!(bulk_operation::get_one))
}

/// The route that resyncs the policy state, merged into [`router`].
fn policy_resync_router<S>() -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    IamState: FromRef<S>,
{
    OpenApiRouter::new().routes(routes!(policy_resync::create))
}

/// The routes that revoke sessions and set the global token cut-off, merged into [`router`].
fn revocation_router<S>() -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    IamState: FromRef<S>,
{
    OpenApiRouter::new()
        .routes(routes!(session_revocation::create))
        .routes(routes!(global_token_cutoff::create))
}

/// The routes of the rate policies, merged into [`router`].
fn rate_policy_router<S>() -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    IamState: FromRef<S>,
{
    OpenApiRouter::new()
        .routes(routes!(rate_policy::create, rate_policy::list))
        .routes(routes!(
            rate_policy::get_one,
            rate_policy::update,
            rate_policy::delete
        ))
}

/// The routes of the upstreams of the gateway configuration, merged into [`router`].
fn upstream_router<S>() -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    IamState: FromRef<S>,
{
    OpenApiRouter::new()
        .routes(routes!(upstream::create, upstream::list))
        .routes(routes!(
            upstream::get_one,
            upstream::update,
            upstream::delete
        ))
}

/// The routes of the routes of the gateway configuration, merged into [`router`].
fn route_router<S>() -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    IamState: FromRef<S>,
{
    OpenApiRouter::new()
        .routes(routes!(route::create, route::list))
        .routes(routes!(route::get_one, route::update, route::delete))
}

/// The routes of the route configuration of a host, merged into [`router`].
fn route_configuration_router<S>() -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    IamState: FromRef<S>,
{
    OpenApiRouter::new()
        .routes(routes!(
            route_configuration::get_one,
            route_configuration::apply
        ))
        .layer(DefaultBodyLimit::max(
            route_configuration::ROUTE_CONFIGURATION_BODY_LIMIT_BYTES,
        ))
}

/// The routes that read the security audit log, merged into [`router`].
fn security_audit_event_router<S>() -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    IamState: FromRef<S>,
{
    OpenApiRouter::new()
        .routes(routes!(security_audit_event::list))
        .routes(routes!(security_audit_event::get_one))
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
