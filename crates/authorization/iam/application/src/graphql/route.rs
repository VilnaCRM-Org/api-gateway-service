//! GraphQL objects and the resolvers of the route operations.
//!
//! The resolvers share the use-case calls and the response shapes of the REST handlers, so both
//! transports apply one set of rules.

use async_graphql::{Context, ID, InputObject, MaybeUndefined, SimpleObject};
use iam_domain::{EnforcementMode, HttpMethod, PolicyVersion, RetryPolicy};
use shared_application::http::{Problem, Violation};
use validator::Validate as _;

use super::propagation::{PropagationObject, WriteOutcomeMapper, write_mode};
use super::{expected_version, idempotency_key, require_caller, state};
use crate::error::IamError;
use crate::http::dto::DEFAULT_PAGE_SIZE;
use crate::http::extract::VersionedWriteHeaders;
use crate::http::route::dto::{
    CorsPolicyDto, CorsUpdate, CreateRouteRequest, DEFAULT_BODY_LIMIT_BYTES,
    DEFAULT_CORS_MAX_AGE_SECONDS, DEFAULT_IDLE_TIMEOUT_MS, DEFAULT_REQUEST_TIMEOUT_MS,
    EnforcementDto, HttpMethodDto, ListRoutesParams, RetryPolicyDto, RoutePageResponse,
    RouteResponse, UpdateRouteRequest,
};
use crate::http::route::{
    create_route, delete_route, find_route, list_routes, parse_route_id, update_route,
};

/// Input of the CORS policy of a route.
#[derive(Debug, InputObject)]
#[graphql(name = "RouteCorsPolicyInput")]
pub struct CorsPolicyInput {
    /// The allowed origins, each an exact `https` (or `http`) origin.
    pub origins: Vec<String>,
    /// The allowed methods, such as `GET`.
    pub methods: Option<Vec<String>>,
    /// The allowed request headers.
    pub headers: Option<Vec<String>>,
    /// Whether credentials are allowed; default `false`.
    pub allow_credentials: Option<bool>,
    /// How long a preflight answer may be cached, in seconds, at most 86,400; default 600.
    pub max_age_seconds: Option<i64>,
}

/// Input of the route-creation mutation.
#[derive(Debug, InputObject)]
#[graphql(name = "CreateRouteInput")]
pub struct CreateRouteInput {
    /// The lower-case DNS name of the host the route serves.
    pub host: String,
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
    /// Makes the creation safe to repeat for 24 hours: 1 to 255 visible ASCII characters.
    pub idempotency_key: Option<String>,
    /// What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions.
    pub consistency: Option<String>,
}

/// Input of the route-update mutation; an absent or null setting keeps its stored value, except
/// `cors`, where null removes the policy.
#[derive(Debug, InputObject)]
#[graphql(name = "UpdateRouteInput")]
pub struct UpdateRouteInput {
    /// The route to change.
    pub id: ID,
    /// The version the caller read; required, and the update is refused when it is not the current one.
    pub expected_version: Option<i64>,
    /// The lower-case DNS name of the host the route serves.
    pub host: Option<String>,
    /// The methods the route serves, such as `GET`.
    pub methods: Option<Vec<String>>,
    /// The path pattern.
    pub path_pattern: Option<String>,
    /// The catalogue service whose keys authorize the route.
    pub service: Option<String>,
    /// The upstream the route forwards to.
    pub upstream_id: Option<ID>,
    /// Whether the route serves GraphQL.
    pub graphql: Option<bool>,
    /// Whether the route streams its response.
    pub streaming: Option<bool>,
    /// Whether the route is served without authentication; changing it needs `iam:route:anonymous`.
    pub anonymous: Option<bool>,
    /// The enforcement mode: `enforce` or `audit`; changing it needs `iam:route:anonymous`.
    pub enforcement: Option<String>,
    /// The largest request body in bytes.
    pub body_limit_bytes: Option<i64>,
    /// The request timeout in milliseconds.
    pub request_timeout_ms: Option<i64>,
    /// The idle timeout in milliseconds.
    pub idle_timeout_ms: Option<i64>,
    /// Which failed requests are retried: `none` or `idempotent`.
    pub retry_policy: Option<String>,
    /// The rate policies of the route, in the order they apply, at most 10.
    pub rate_policy_ids: Option<Vec<ID>>,
    /// The CORS policy of the route; null removes it.
    pub cors: MaybeUndefined<CorsPolicyInput>,
    /// Makes the update safe to repeat for 24 hours: 1 to 255 visible ASCII characters.
    pub idempotency_key: Option<String>,
    /// What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions.
    pub consistency: Option<String>,
}

/// Input of the route-deletion mutation.
#[derive(Debug, InputObject)]
#[graphql(name = "DeleteRouteInput")]
pub struct DeleteRouteInput {
    /// The route to delete.
    pub id: ID,
    /// The version the caller read; required, and the deletion is refused when it is not the current one.
    pub expected_version: Option<i64>,
    /// Makes the deletion safe to repeat for 24 hours: 1 to 255 visible ASCII characters.
    pub idempotency_key: Option<String>,
    /// What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions.
    pub consistency: Option<String>,
}

/// The result of a route deletion.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "DeleteRoutePayload")]
pub struct DeleteRoutePayload {
    /// The identifier of the deleted route.
    pub id: ID,
    /// The final version of the route.
    pub version: i64,
    /// The policy version that the deletion produced.
    pub policy_version: Option<i64>,
    /// What the deletion learned about the publication of its policy version.
    pub propagation: Option<PropagationObject>,
}

/// The CORS policy of a route.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "RouteCorsPolicy")]
pub struct CorsPolicyObject {
    /// The allowed origins.
    pub origins: Vec<String>,
    /// The allowed methods.
    pub methods: Vec<String>,
    /// The allowed request headers.
    pub headers: Vec<String>,
    /// Whether credentials are allowed.
    pub allow_credentials: bool,
    /// How long a preflight answer may be cached, in seconds.
    pub max_age_seconds: i64,
}

impl From<CorsPolicyDto> for CorsPolicyObject {
    fn from(cors: CorsPolicyDto) -> Self {
        Self {
            origins: cors.origins,
            methods: methods_text(cors.methods),
            headers: cors.headers,
            allow_credentials: cors.allow_credentials,
            max_age_seconds: cors.max_age_seconds,
        }
    }
}

/// The names of the methods.
fn methods_text(methods: Vec<HttpMethodDto>) -> Vec<String> {
    methods
        .into_iter()
        .map(|method| HttpMethod::from(method).as_str().to_owned())
        .collect()
}

/// How the gateway carries the traffic of a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SimpleObject)]
#[graphql(name = "RouteTraffic")]
pub struct RouteTrafficObject {
    /// Whether the route serves GraphQL.
    pub graphql: bool,
    /// Whether the route streams its response.
    pub streaming: bool,
}

/// A route of the gateway configuration.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "Route")]
pub struct RouteObject {
    /// The identifier of the route.
    pub id: ID,
    /// The host the route serves.
    pub host: String,
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
    /// Whether IAM manages the route itself; the API refuses every change of a system route.
    pub system: bool,
    /// The version of the route.
    pub version: i64,
    /// When the route was created, as an RFC 3339 UTC time.
    pub created_at: String,
    /// When the route was last changed, as an RFC 3339 UTC time.
    pub updated_at: String,
    /// What the write that returned the route learned about the publication of its policy version; null for a read.
    pub propagation: Option<PropagationObject>,
}

impl From<RouteResponse> for RouteObject {
    fn from(response: RouteResponse) -> Self {
        Self {
            id: ID::from(response.id),
            host: response.host,
            methods: methods_text(response.methods),
            path_pattern: response.path_pattern,
            service: response.service,
            upstream_id: ID::from(response.upstream_id),
            traffic: RouteTrafficObject {
                graphql: response.traffic.graphql,
                streaming: response.traffic.streaming,
            },
            anonymous: response.anonymous,
            enforcement: EnforcementMode::from(response.enforcement)
                .as_str()
                .to_owned(),
            body_limit_bytes: i64::try_from(response.body_limit_bytes).unwrap_or(i64::MAX),
            request_timeout_ms: i64::from(response.request_timeout_ms),
            idle_timeout_ms: i64::from(response.idle_timeout_ms),
            retry_policy: RetryPolicy::from(response.retry_policy).as_str().to_owned(),
            rate_policy_ids: response.rate_policy_ids.into_iter().map(ID::from).collect(),
            cors: response.cors.map(CorsPolicyObject::from),
            system: response.system,
            version: response.version,
            created_at: response.created_at,
            updated_at: response.updated_at,
            propagation: None,
        }
    }
}

/// One page of routes.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "RoutePage")]
pub struct RoutePageObject {
    /// The routes of the page.
    pub items: Vec<RouteObject>,
    /// The `after` value of the next page; null on the last page.
    pub next_cursor: Option<String>,
}

impl From<RoutePageResponse> for RoutePageObject {
    fn from(page: RoutePageResponse) -> Self {
        Self {
            items: page.items.into_iter().map(RouteObject::from).collect(),
            next_cursor: page.next_cursor,
        }
    }
}

/// The violation of `property` that names the allowed values.
fn choice(property: &str, allowed: &str) -> IamError {
    IamError::Invalid(vec![Violation {
        property_path: property.to_owned(),
        message: format!("This value must be {allowed}."),
        code: "choice".to_owned(),
    }])
}

/// The method that the text names.
fn method_of(text: &str) -> Result<HttpMethodDto, IamError> {
    HttpMethod::parse(text)
        .map(HttpMethodDto::from)
        .ok_or_else(|| choice("methods", "GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS"))
}

/// The methods that the texts name.
fn methods_of(texts: &[String]) -> Result<Vec<HttpMethodDto>, IamError> {
    texts.iter().map(|text| method_of(text)).collect()
}

/// The enforcement mode that the text names.
fn enforcement_of(text: &str) -> Result<EnforcementDto, IamError> {
    EnforcementMode::parse(text)
        .map(EnforcementDto::from)
        .ok_or_else(|| choice("enforcement", "enforce or audit"))
}

/// The retry policy that the text names.
fn retry_of(text: &str) -> Result<RetryPolicyDto, IamError> {
    RetryPolicy::parse(text)
        .map(RetryPolicyDto::from)
        .ok_or_else(|| choice("retryPolicy", "none or idempotent"))
}

/// The identifiers as the texts of a request.
fn texts_of(ids: Vec<ID>) -> Vec<String> {
    ids.into_iter().map(|id| id.as_str().to_owned()).collect()
}

/// The CORS policy that the input describes.
fn cors_of(input: CorsPolicyInput) -> Result<CorsPolicyDto, IamError> {
    Ok(CorsPolicyDto {
        origins: input.origins,
        methods: input
            .methods
            .as_deref()
            .map(methods_of)
            .transpose()?
            .unwrap_or_default(),
        headers: input.headers.unwrap_or_default(),
        allow_credentials: input.allow_credentials.unwrap_or(false),
        max_age_seconds: input
            .max_age_seconds
            .unwrap_or(DEFAULT_CORS_MAX_AGE_SECONDS),
    })
}

/// The creation request that the input describes.
fn create_request_of(input: CreateRouteInput) -> Result<CreateRouteRequest, IamError> {
    Ok(CreateRouteRequest {
        host: input.host,
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

/// The update request that the input describes.
fn update_request_of(input: UpdateRouteInput) -> Result<UpdateRouteRequest, IamError> {
    Ok(UpdateRouteRequest {
        host: input.host,
        methods: input.methods.as_deref().map(methods_of).transpose()?,
        path_pattern: input.path_pattern,
        service: input.service,
        upstream_id: input.upstream_id.map(|id| id.as_str().to_owned()),
        graphql: input.graphql,
        streaming: input.streaming,
        anonymous: input.anonymous,
        enforcement: input
            .enforcement
            .as_deref()
            .map(enforcement_of)
            .transpose()?,
        body_limit_bytes: input.body_limit_bytes,
        request_timeout_ms: input.request_timeout_ms,
        idle_timeout_ms: input.idle_timeout_ms,
        retry_policy: input.retry_policy.as_deref().map(retry_of).transpose()?,
        rate_policy_ids: input.rate_policy_ids.map(texts_of),
        cors: match input.cors {
            MaybeUndefined::Undefined => CorsUpdate::Keep,
            MaybeUndefined::Null => CorsUpdate::Remove,
            MaybeUndefined::Value(cors) => CorsUpdate::Set(cors_of(cors)?),
        },
    })
}

/// Creates a route as the caller of the request.
pub(super) async fn create_route_field(
    ctx: &Context<'_>,
    input: CreateRouteInput,
) -> Result<RouteObject, Problem> {
    let caller = require_caller(ctx)?;
    let key = idempotency_key(input.idempotency_key.as_deref())?;
    let consistency = input.consistency.clone();
    let request = create_request_of(input)?;
    request.validate()?;
    write_mode(consistency.as_deref())?;
    let (route, receipt) = create_route(state(ctx)?, caller, key, request).await?;
    Ok(RouteObject {
        propagation: WriteOutcomeMapper::propagation(&receipt),
        ..RouteObject::from(RouteResponse::from(route))
    })
}

/// Reads one route; none when it is unknown or deleted.
pub(super) async fn route_field(
    ctx: &Context<'_>,
    id: &ID,
) -> Result<Option<RouteObject>, Problem> {
    require_caller(ctx)?;
    let route = find_route(state(ctx)?, parse_route_id(id.as_str())?).await?;
    Ok(route.map(|route| RouteObject::from(RouteResponse::from(route))))
}

/// Reads one page of routes.
pub(super) async fn routes_field(
    ctx: &Context<'_>,
    first: Option<i32>,
    after: Option<String>,
    filter: RouteFilterInput,
) -> Result<RoutePageObject, Problem> {
    require_caller(ctx)?;
    let params = ListRoutesParams {
        limit: first.unwrap_or(DEFAULT_PAGE_SIZE),
        after,
        host: filter.host,
        upstream: filter.upstream.map(|id| id.as_str().to_owned()),
        service: filter.service,
    };
    params.validate()?;
    let page = list_routes(state(ctx)?, params).await?;
    Ok(RoutePageObject::from(RoutePageResponse::from(page)))
}

/// The filters of the route list: a route must match every one that is given.
#[derive(Debug, Default, InputObject)]
#[graphql(name = "RouteFilterInput")]
pub struct RouteFilterInput {
    /// Only the routes of this host.
    pub host: Option<String>,
    /// Only the routes that forward to this upstream.
    pub upstream: Option<ID>,
    /// Only the routes of this catalogue service.
    pub service: Option<String>,
}

/// Changes the configuration of a route as the caller of the request.
pub(super) async fn update_route_field(
    ctx: &Context<'_>,
    input: UpdateRouteInput,
) -> Result<RouteObject, Problem> {
    let caller = require_caller(ctx)?;
    let expected = expected_version(input.expected_version)?;
    let id = parse_route_id(input.id.as_str())?;
    let key = idempotency_key(input.idempotency_key.as_deref())?;
    let consistency = input.consistency.clone();
    let request = update_request_of(input)?;
    request.validate()?;
    write_mode(consistency.as_deref())?;
    let headers = VersionedWriteHeaders { expected, key };
    let (route, receipt) = update_route(state(ctx)?, caller, id, headers, request).await?;
    Ok(RouteObject {
        propagation: WriteOutcomeMapper::propagation(&receipt),
        ..RouteObject::from(RouteResponse::from(route))
    })
}

/// Deletes a route as the caller of the request.
pub(super) async fn delete_route_field(
    ctx: &Context<'_>,
    input: DeleteRouteInput,
) -> Result<DeleteRoutePayload, Problem> {
    let caller = require_caller(ctx)?;
    let expected = expected_version(input.expected_version)?;
    let id = parse_route_id(input.id.as_str())?;
    let key = idempotency_key(input.idempotency_key.as_deref())?;
    write_mode(input.consistency.as_deref())?;
    let headers = VersionedWriteHeaders { expected, key };
    let receipt = delete_route(state(ctx)?, caller, id, headers).await?;
    Ok(DeleteRoutePayload {
        id: ID::from(receipt.target().target_id()),
        version: receipt.entity_version().value(),
        policy_version: receipt.policy_version().map(PolicyVersion::value),
        propagation: WriteOutcomeMapper::propagation(&receipt),
    })
}
