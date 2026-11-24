//! GraphQL objects and the resolvers of the route-configuration operations (FR-58).
//!
//! The resolvers share the use-case calls and the response shapes of the REST handlers, so both
//! transports apply one set of rules.

use async_graphql::{Context, ID, InputObject, SimpleObject};
use iam_domain::{ChangeReceipt, EnforcementMode, PolicyVersion, RetryPolicy};
use shared_application::http::Problem;
use validator::Validate as _;

use super::propagation::{PropagationObject, WriteOutcomeMapper, write_mode};
use super::route::{
    CorsPolicyInput, CorsPolicyObject, RouteTrafficObject, cors_of, enforcement_of, methods_of,
    methods_text, retry_of, texts_of,
};
use super::{expected_version, require_caller, state};
use crate::command::route_configuration_plan::indexed;
use crate::error::IamError;
use crate::http::route::dto::{
    DEFAULT_BODY_LIMIT_BYTES, DEFAULT_IDLE_TIMEOUT_MS, DEFAULT_REQUEST_TIMEOUT_MS, EnforcementDto,
    RetryPolicyDto,
};
use crate::http::route_configuration::dto::{
    ApplyRouteConfigurationRequest, RouteChangeDto, RouteConfigurationDiffResponse,
    RouteConfigurationResponse, RouteDeclarationDto,
};
use crate::http::route_configuration::{
    RouteConfigurationWrite, apply_route_configuration, get_route_configuration,
};

/// Input of one route of a declared set.
#[derive(Debug, InputObject)]
#[graphql(name = "RouteDeclarationInput")]
pub struct RouteDeclarationInput {
    /// The methods the route serves, such as `GET`.
    pub methods: Vec<String>,
    /// The path pattern, with `{name}` and `{name:*}` segments.
    pub path_pattern: String,
    /// The catalogue service whose keys authorize the route; it must equal the catalogue service of the upstream.
    pub service: String,
    /// The upstream the route forwards to.
    pub upstream_id: ID,
    /// Whether the route serves GraphQL; default `false`.
    pub graphql: Option<bool>,
    /// Whether the route streams its response; default `false`.
    pub streaming: Option<bool>,
    /// Whether the route is served without authentication; needs `iam:route:anonymous`; default `false`.
    pub anonymous: Option<bool>,
    /// The enforcement mode: `enforce` (the default) or `audit`, which needs `iam:route:anonymous`.
    pub enforcement: Option<String>,
    /// The largest request body in bytes; default 1,048,576.
    pub body_limit_bytes: Option<i64>,
    /// The request timeout in milliseconds; default 30,000.
    pub request_timeout_ms: Option<i64>,
    /// The idle timeout in milliseconds; default 60,000.
    pub idle_timeout_ms: Option<i64>,
    /// Which failed requests are retried: `none` (the default) or `idempotent`.
    pub retry_policy: Option<String>,
    /// The rate policies of the route, in the order they apply, at most 10.
    pub rate_policy_ids: Option<Vec<ID>>,
    /// The CORS policy of the route.
    pub cors: Option<CorsPolicyInput>,
}

/// Input of the route-configuration mutation.
#[derive(Debug, InputObject)]
#[graphql(name = "ApplyRouteConfigurationInput")]
pub struct ApplyRouteConfigurationInput {
    /// The lower-case DNS name of the host whose routes the set replaces.
    pub host: String,
    /// The routes the host has afterwards, at most `ROUTE_CONFIGURATION_MAX_ROUTES` (1,000 by default); a stored route that the set does not declare is deleted.
    pub routes: Vec<RouteDeclarationInput>,
    /// The version of the set that the caller read (`routeConfiguration.version`); required, and the application is refused when it is not the current one.
    pub expected_version: Option<i64>,
    /// Returns the diff and writes nothing; default `false`.
    pub dry_run: Option<bool>,
    /// What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions.
    pub consistency: Option<String>,
}

/// One route of a set, in the form that the application accepts.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "RouteDeclaration")]
pub struct RouteDeclarationObject {
    /// The methods the route serves.
    pub methods: Vec<String>,
    /// The path pattern.
    pub path_pattern: String,
    /// The catalogue service whose keys authorize the route.
    pub service: String,
    /// The upstream the route forwards to.
    pub upstream_id: ID,
    /// Whether the route serves GraphQL and whether it streams its response.
    #[graphql(flatten)]
    pub traffic: RouteTrafficObject,
    /// Whether the route is served without authentication.
    pub anonymous: bool,
    /// The enforcement mode: `enforce` or `audit`.
    pub enforcement: String,
    /// The largest request body in bytes.
    pub body_limit_bytes: i64,
    /// The request timeout in milliseconds.
    pub request_timeout_ms: i64,
    /// The idle timeout in milliseconds.
    pub idle_timeout_ms: i64,
    /// Which failed requests are retried: `none` or `idempotent`.
    pub retry_policy: String,
    /// The rate policies of the route, in the order they apply.
    pub rate_policy_ids: Vec<ID>,
    /// The CORS policy of the route; null when it has none.
    pub cors: Option<CorsPolicyObject>,
}

impl From<RouteDeclarationDto> for RouteDeclarationObject {
    fn from(route: RouteDeclarationDto) -> Self {
        Self {
            methods: methods_text(route.methods),
            path_pattern: route.path_pattern,
            service: route.service,
            upstream_id: ID::from(route.upstream_id),
            traffic: RouteTrafficObject {
                graphql: route.graphql.unwrap_or(false),
                streaming: route.streaming.unwrap_or(false),
            },
            anonymous: route.anonymous.unwrap_or(false),
            enforcement: EnforcementMode::from(route.enforcement).as_str().to_owned(),
            body_limit_bytes: route.body_limit_bytes,
            request_timeout_ms: route.request_timeout_ms,
            idle_timeout_ms: route.idle_timeout_ms,
            retry_policy: RetryPolicy::from(route.retry_policy).as_str().to_owned(),
            rate_policy_ids: route.rate_policy_ids.into_iter().map(ID::from).collect(),
            cors: route.cors.map(CorsPolicyObject::from),
        }
    }
}

/// The route set of a host and its version.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "RouteConfiguration")]
pub struct RouteConfigurationObject {
    /// The host.
    pub host: String,
    /// The version of the set, to pass as `expectedVersion` of the next application.
    pub version: i64,
    /// The routes of the host, in the form that the application accepts.
    pub routes: Vec<RouteDeclarationObject>,
}

impl From<RouteConfigurationResponse> for RouteConfigurationObject {
    fn from(configuration: RouteConfigurationResponse) -> Self {
        Self {
            host: configuration.host,
            version: configuration.version,
            routes: configuration
                .routes
                .into_iter()
                .map(RouteDeclarationObject::from)
                .collect(),
        }
    }
}

/// A route that a set adds, changes or removes.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "RouteConfigurationChange")]
pub struct RouteChangeObject {
    /// The methods of the route.
    pub methods: Vec<String>,
    /// The path pattern of the route.
    pub path_pattern: String,
    /// The names of the properties that change; empty unless the route is changed.
    pub changed_fields: Vec<String>,
}

impl From<RouteChangeDto> for RouteChangeObject {
    fn from(change: RouteChangeDto) -> Self {
        Self {
            methods: methods_text(change.methods),
            path_pattern: change.path_pattern,
            changed_fields: change.changed_fields,
        }
    }
}

/// The result of the route-configuration mutation.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "ApplyRouteConfigurationPayload")]
pub struct ApplyRouteConfigurationPayload {
    /// The host.
    pub host: String,
    /// Whether the request was a dry run, which wrote nothing.
    pub dry_run: bool,
    /// The version of the set of the host: the version after an applied set, the stored version after a dry run or a set that changes nothing.
    pub version: i64,
    /// The number of routes the host has, or would have after a dry run.
    pub route_count: i64,
    /// Whether the diff deletes a route, clears `anonymous` or moves `enforcement` from `audit` to `enforce`, which makes the application revocation-class.
    pub revocation: bool,
    /// The number of declared routes that equal a stored route.
    pub unchanged: i64,
    /// The routes the set creates.
    pub added: Vec<RouteChangeObject>,
    /// The routes the set updates.
    pub changed: Vec<RouteChangeObject>,
    /// The routes the set deletes.
    pub removed: Vec<RouteChangeObject>,
    /// The policy version that the application produced; null for a dry run and for a set that changes nothing.
    pub policy_version: Option<i64>,
    /// What the application learned about the publication of its policy version; null for a dry run and for a set that changes nothing.
    pub propagation: Option<PropagationObject>,
}

impl From<RouteConfigurationDiffResponse> for ApplyRouteConfigurationPayload {
    fn from(diff: RouteConfigurationDiffResponse) -> Self {
        Self {
            host: diff.host,
            dry_run: diff.dry_run,
            version: diff.version,
            route_count: i64::try_from(diff.route_count).unwrap_or(i64::MAX),
            revocation: diff.revocation,
            unchanged: i64::try_from(diff.unchanged).unwrap_or(i64::MAX),
            added: diff
                .added
                .into_iter()
                .map(RouteChangeObject::from)
                .collect(),
            changed: diff
                .changed
                .into_iter()
                .map(RouteChangeObject::from)
                .collect(),
            removed: diff
                .removed
                .into_iter()
                .map(RouteChangeObject::from)
                .collect(),
            policy_version: None,
            propagation: None,
        }
    }
}

/// The declaration that the input describes.
fn declaration_of(input: RouteDeclarationInput) -> Result<RouteDeclarationDto, IamError> {
    Ok(RouteDeclarationDto {
        methods: methods_of(&input.methods)?,
        path_pattern: input.path_pattern,
        service: input.service,
        upstream_id: input.upstream_id.as_str().to_owned(),
        graphql: input.graphql,
        streaming: input.streaming,
        anonymous: input.anonymous,
        enforcement: input
            .enforcement
            .as_deref()
            .map(enforcement_of)
            .transpose()?
            .unwrap_or(EnforcementDto::Enforce),
        body_limit_bytes: input.body_limit_bytes.unwrap_or(DEFAULT_BODY_LIMIT_BYTES),
        request_timeout_ms: input
            .request_timeout_ms
            .unwrap_or(DEFAULT_REQUEST_TIMEOUT_MS),
        idle_timeout_ms: input.idle_timeout_ms.unwrap_or(DEFAULT_IDLE_TIMEOUT_MS),
        retry_policy: input
            .retry_policy
            .as_deref()
            .map(retry_of)
            .transpose()?
            .unwrap_or(RetryPolicyDto::None),
        rate_policy_ids: texts_of(input.rate_policy_ids.unwrap_or_default()),
        cors: input.cors.map(cors_of).transpose()?,
    })
}

/// The request that the routes of the input describe; a route that cannot be read names its
/// position in the set.
fn request_of(
    routes: Vec<RouteDeclarationInput>,
) -> Result<ApplyRouteConfigurationRequest, IamError> {
    let routes = routes
        .into_iter()
        .enumerate()
        .map(|(index, route)| declaration_of(route).map_err(|error| indexed(index, error)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ApplyRouteConfigurationRequest { routes })
}

/// Reads the route set of a host.
pub(super) async fn route_configuration_field(
    ctx: &Context<'_>,
    host: &str,
) -> Result<RouteConfigurationObject, Problem> {
    require_caller(ctx)?;
    let configuration = get_route_configuration(state(ctx)?, host).await?;
    Ok(RouteConfigurationObject::from(
        RouteConfigurationResponse::from(configuration),
    ))
}

/// Replaces the route set of a host as the caller of the request, or reports the diff of a dry
/// run.
pub(super) async fn apply_route_configuration_field(
    ctx: &Context<'_>,
    input: ApplyRouteConfigurationInput,
) -> Result<ApplyRouteConfigurationPayload, Problem> {
    let caller = require_caller(ctx)?;
    let expected = expected_version(input.expected_version)?;
    let dry_run = input.dry_run.unwrap_or(false);
    let request = request_of(input.routes)?;
    request.validate()?;
    write_mode(input.consistency.as_deref())?;
    let write = RouteConfigurationWrite {
        host: &input.host,
        expected,
        dry_run,
        request,
    };
    let applied = apply_route_configuration(state(ctx)?, caller, write).await?;
    let response = RouteConfigurationDiffResponse::of(
        &applied.preview,
        dry_run,
        applied
            .receipt
            .as_ref()
            .map(|receipt| receipt.entity_version().value()),
    );
    Ok(ApplyRouteConfigurationPayload {
        policy_version: applied
            .receipt
            .as_ref()
            .and_then(ChangeReceipt::policy_version)
            .map(PolicyVersion::value),
        propagation: applied
            .receipt
            .as_ref()
            .and_then(WriteOutcomeMapper::propagation),
        ..ApplyRouteConfigurationPayload::from(response)
    })
}
