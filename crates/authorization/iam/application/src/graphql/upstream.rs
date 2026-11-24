//! GraphQL objects and the resolvers of the upstream operations.
//!
//! The resolvers share the use-case calls and the response shapes of the REST handlers, so both
//! transports apply one set of rules.

use async_graphql::{Context, ID, InputObject, SimpleObject};
use iam_domain::{PolicyVersion, UpstreamProtocol};
use shared_application::http::{Problem, Violation};
use validator::Validate as _;

use super::propagation::{PropagationObject, WriteOutcomeMapper, write_mode};
use super::{expected_version, idempotency_key, require_caller, state};
use crate::error::IamError;
use crate::http::dto::DEFAULT_PAGE_SIZE;
use crate::http::extract::VersionedWriteHeaders;
use crate::http::upstream::dto::{
    CreateUpstreamRequest, DEFAULT_CONCURRENCY_LIMIT, DEFAULT_CONNECT_TIMEOUT_MS,
    DEFAULT_OUTLIER_CONSECUTIVE_ERRORS, DEFAULT_RESPONSE_TIMEOUT_MS, DEFAULT_RETRY_BUDGET_PERCENT,
    ListUpstreamsParams, UpdateUpstreamRequest, UpstreamPageResponse, UpstreamProtocolDto,
    UpstreamResponse,
};
use crate::http::upstream::{
    create_upstream, delete_upstream, find_upstream, list_upstreams, parse_upstream_id,
    update_upstream,
};

/// Input of the upstream-creation mutation.
#[derive(Debug, InputObject)]
#[graphql(name = "CreateUpstreamInput")]
pub struct CreateUpstreamInput {
    /// The name of the upstream: a service name such as `core`, 1 to 63 characters, unique among the upstreams that are not deleted.
    pub name: String,
    /// The Kubernetes namespace of the Service.
    pub namespace: String,
    /// The Kubernetes Service that the gateway proxies to.
    pub service: String,
    /// The catalogue service whose keys authorize the routes of this upstream.
    pub catalog_service: String,
    /// Whether the credentials of the caller are forwarded to the upstream; default `false`.
    pub forward_credentials: Option<bool>,
    /// The port of the Service, from 1 to 65,535.
    pub port: i64,
    /// The protocol the gateway speaks to the upstream: `http1` or `h2c`.
    pub protocol: String,
    /// The connect timeout in milliseconds; default 250.
    pub connect_timeout_ms: Option<i64>,
    /// The response timeout in milliseconds; default 10,000.
    pub response_timeout_ms: Option<i64>,
    /// The largest number of concurrent requests to the upstream; default 256.
    pub concurrency_limit: Option<i64>,
    /// The retry budget in percent of the requests, from 0 to 100; default 10.
    pub retry_budget_percent: Option<i64>,
    /// The number of consecutive failures after which an endpoint is ejected; default 5.
    pub outlier_consecutive_errors: Option<i64>,
    /// Makes the creation safe to repeat for 24 hours: 1 to 255 visible ASCII characters.
    pub idempotency_key: Option<String>,
    /// What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions.
    pub consistency: Option<String>,
}

/// Input of the upstream-update mutation; an absent or null setting keeps its stored value.
#[derive(Debug, InputObject)]
#[graphql(name = "UpdateUpstreamInput")]
pub struct UpdateUpstreamInput {
    /// The upstream to change.
    pub id: ID,
    /// The version the caller read; required, and the update is refused when it is not the current one.
    pub expected_version: Option<i64>,
    /// The name of the upstream; it must equal the stored name, because the name cannot change.
    pub name: Option<String>,
    /// The Kubernetes namespace of the Service.
    pub namespace: Option<String>,
    /// The Kubernetes Service that the gateway proxies to.
    pub service: Option<String>,
    /// The catalogue service whose keys authorize the routes of this upstream.
    pub catalog_service: Option<String>,
    /// Whether the credentials of the caller are forwarded to the upstream.
    pub forward_credentials: Option<bool>,
    /// The port of the Service, from 1 to 65,535.
    pub port: Option<i64>,
    /// The protocol the gateway speaks to the upstream: `http1` or `h2c`.
    pub protocol: Option<String>,
    /// The connect timeout in milliseconds.
    pub connect_timeout_ms: Option<i64>,
    /// The response timeout in milliseconds.
    pub response_timeout_ms: Option<i64>,
    /// The largest number of concurrent requests to the upstream.
    pub concurrency_limit: Option<i64>,
    /// The retry budget in percent of the requests, from 0 to 100.
    pub retry_budget_percent: Option<i64>,
    /// The number of consecutive failures after which an endpoint is ejected.
    pub outlier_consecutive_errors: Option<i64>,
    /// Makes the update safe to repeat for 24 hours: 1 to 255 visible ASCII characters.
    pub idempotency_key: Option<String>,
    /// What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions.
    pub consistency: Option<String>,
}

/// Input of the upstream-deletion mutation.
#[derive(Debug, InputObject)]
#[graphql(name = "DeleteUpstreamInput")]
pub struct DeleteUpstreamInput {
    /// The upstream to delete.
    pub id: ID,
    /// The version the caller read; required, and the deletion is refused when it is not the current one.
    pub expected_version: Option<i64>,
    /// Makes the deletion safe to repeat for 24 hours: 1 to 255 visible ASCII characters.
    pub idempotency_key: Option<String>,
    /// What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions.
    pub consistency: Option<String>,
}

/// The result of an upstream deletion.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "DeleteUpstreamPayload")]
pub struct DeleteUpstreamPayload {
    /// The identifier of the deleted upstream.
    pub id: ID,
    /// The final version of the upstream.
    pub version: i64,
    /// The policy version that the deletion produced.
    pub policy_version: Option<i64>,
    /// What the deletion learned about the publication of its policy version.
    pub propagation: Option<PropagationObject>,
}

/// An upstream of the gateway configuration.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "Upstream")]
pub struct UpstreamObject {
    /// The identifier of the upstream.
    pub id: ID,
    /// The name of the upstream.
    pub name: String,
    /// The Kubernetes namespace of the Service.
    pub namespace: String,
    /// The Kubernetes Service that the gateway proxies to.
    pub service: String,
    /// The catalogue service whose keys authorize the routes of this upstream.
    pub catalog_service: String,
    /// Whether the credentials of the caller are forwarded to the upstream.
    pub forward_credentials: bool,
    /// The port of the Service.
    pub port: i32,
    /// The protocol the gateway speaks to the upstream: `http1` or `h2c`.
    pub protocol: String,
    /// The connect timeout in milliseconds.
    pub connect_timeout_ms: i64,
    /// The response timeout in milliseconds.
    pub response_timeout_ms: i64,
    /// The largest number of concurrent requests to the upstream.
    pub concurrency_limit: i64,
    /// The retry budget in percent of the requests.
    pub retry_budget_percent: i32,
    /// The number of consecutive failures after which an endpoint is ejected.
    pub outlier_consecutive_errors: i64,
    /// Whether IAM manages the upstream itself; the API refuses every change of a system upstream.
    pub system: bool,
    /// The version of the upstream.
    pub version: i64,
    /// When the upstream was created, as an RFC 3339 UTC time.
    pub created_at: String,
    /// When the upstream was last changed, as an RFC 3339 UTC time.
    pub updated_at: String,
    /// What the write that returned the upstream learned about the publication of its policy version; null for a read.
    pub propagation: Option<PropagationObject>,
}

impl From<UpstreamResponse> for UpstreamObject {
    fn from(response: UpstreamResponse) -> Self {
        Self {
            id: ID::from(response.id),
            name: response.name,
            namespace: response.namespace,
            service: response.service,
            catalog_service: response.catalog_service,
            forward_credentials: response.forward_credentials,
            port: i32::from(response.port),
            protocol: UpstreamProtocol::from(response.protocol)
                .as_str()
                .to_owned(),
            connect_timeout_ms: i64::from(response.connect_timeout_ms),
            response_timeout_ms: i64::from(response.response_timeout_ms),
            concurrency_limit: i64::from(response.concurrency_limit),
            retry_budget_percent: i32::from(response.retry_budget_percent),
            outlier_consecutive_errors: i64::from(response.outlier_consecutive_errors),
            system: response.system,
            version: response.version,
            created_at: response.created_at,
            updated_at: response.updated_at,
            propagation: None,
        }
    }
}

/// One page of upstreams.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "UpstreamPage")]
pub struct UpstreamPageObject {
    /// The upstreams of the page.
    pub items: Vec<UpstreamObject>,
    /// The `after` value of the next page; null on the last page.
    pub next_cursor: Option<String>,
}

impl From<UpstreamPageResponse> for UpstreamPageObject {
    fn from(page: UpstreamPageResponse) -> Self {
        Self {
            items: page.items.into_iter().map(UpstreamObject::from).collect(),
            next_cursor: page.next_cursor,
        }
    }
}

/// The protocol that the text names.
///
/// # Errors
///
/// [`IamError::Invalid`] with a violation of `protocol` for any text but `http1` and `h2c`.
fn protocol_of(text: &str) -> Result<UpstreamProtocolDto, IamError> {
    UpstreamProtocol::parse(text)
        .map(UpstreamProtocolDto::from)
        .ok_or_else(|| {
            IamError::Invalid(vec![Violation {
                property_path: "protocol".to_owned(),
                message: "This value must be http1 or h2c.".to_owned(),
                code: "choice".to_owned(),
            }])
        })
}

/// Creates an upstream as the caller of the request.
pub(super) async fn create_upstream_field(
    ctx: &Context<'_>,
    input: CreateUpstreamInput,
) -> Result<UpstreamObject, Problem> {
    let caller = require_caller(ctx)?;
    let key = idempotency_key(input.idempotency_key.as_deref())?;
    let request = CreateUpstreamRequest {
        name: input.name,
        namespace: input.namespace,
        service: input.service,
        catalog_service: input.catalog_service,
        forward_credentials: input.forward_credentials.unwrap_or(false),
        port: input.port,
        protocol: protocol_of(&input.protocol)?,
        connect_timeout_ms: input
            .connect_timeout_ms
            .unwrap_or(DEFAULT_CONNECT_TIMEOUT_MS),
        response_timeout_ms: input
            .response_timeout_ms
            .unwrap_or(DEFAULT_RESPONSE_TIMEOUT_MS),
        concurrency_limit: input.concurrency_limit.unwrap_or(DEFAULT_CONCURRENCY_LIMIT),
        retry_budget_percent: input
            .retry_budget_percent
            .unwrap_or(DEFAULT_RETRY_BUDGET_PERCENT),
        outlier_consecutive_errors: input
            .outlier_consecutive_errors
            .unwrap_or(DEFAULT_OUTLIER_CONSECUTIVE_ERRORS),
    };
    request.validate()?;
    write_mode(input.consistency.as_deref())?;
    let (upstream, receipt) = create_upstream(state(ctx)?, caller, key, request).await?;
    Ok(UpstreamObject {
        propagation: WriteOutcomeMapper::propagation(&receipt),
        ..UpstreamObject::from(UpstreamResponse::from(upstream))
    })
}

/// Reads one upstream; none when it is unknown or deleted.
pub(super) async fn upstream_field(
    ctx: &Context<'_>,
    id: &ID,
) -> Result<Option<UpstreamObject>, Problem> {
    require_caller(ctx)?;
    let upstream = find_upstream(state(ctx)?, parse_upstream_id(id.as_str())?).await?;
    Ok(upstream.map(|upstream| UpstreamObject::from(UpstreamResponse::from(upstream))))
}

/// Reads one page of upstreams.
pub(super) async fn upstreams_field(
    ctx: &Context<'_>,
    first: Option<i32>,
    after: Option<String>,
) -> Result<UpstreamPageObject, Problem> {
    require_caller(ctx)?;
    let params = ListUpstreamsParams {
        limit: first.unwrap_or(DEFAULT_PAGE_SIZE),
        after,
    };
    params.validate()?;
    let page = list_upstreams(state(ctx)?, params).await?;
    Ok(UpstreamPageObject::from(UpstreamPageResponse::from(page)))
}

/// Changes the settings of an upstream as the caller of the request.
pub(super) async fn update_upstream_field(
    ctx: &Context<'_>,
    input: UpdateUpstreamInput,
) -> Result<UpstreamObject, Problem> {
    let caller = require_caller(ctx)?;
    let expected = expected_version(input.expected_version)?;
    let id = parse_upstream_id(input.id.as_str())?;
    let key = idempotency_key(input.idempotency_key.as_deref())?;
    let request = UpdateUpstreamRequest {
        name: input.name,
        namespace: input.namespace,
        service: input.service,
        catalog_service: input.catalog_service,
        forward_credentials: input.forward_credentials,
        port: input.port,
        protocol: input.protocol.as_deref().map(protocol_of).transpose()?,
        connect_timeout_ms: input.connect_timeout_ms,
        response_timeout_ms: input.response_timeout_ms,
        concurrency_limit: input.concurrency_limit,
        retry_budget_percent: input.retry_budget_percent,
        outlier_consecutive_errors: input.outlier_consecutive_errors,
    };
    request.validate()?;
    write_mode(input.consistency.as_deref())?;
    let headers = VersionedWriteHeaders { expected, key };
    let (upstream, receipt) = update_upstream(state(ctx)?, caller, id, headers, request).await?;
    Ok(UpstreamObject {
        propagation: WriteOutcomeMapper::propagation(&receipt),
        ..UpstreamObject::from(UpstreamResponse::from(upstream))
    })
}

/// Deletes an upstream as the caller of the request.
pub(super) async fn delete_upstream_field(
    ctx: &Context<'_>,
    input: DeleteUpstreamInput,
) -> Result<DeleteUpstreamPayload, Problem> {
    let caller = require_caller(ctx)?;
    let expected = expected_version(input.expected_version)?;
    let id = parse_upstream_id(input.id.as_str())?;
    let key = idempotency_key(input.idempotency_key.as_deref())?;
    write_mode(input.consistency.as_deref())?;
    let headers = VersionedWriteHeaders { expected, key };
    let receipt = delete_upstream(state(ctx)?, caller, id, headers).await?;
    Ok(DeleteUpstreamPayload {
        id: ID::from(receipt.target().target_id()),
        version: receipt.entity_version().value(),
        policy_version: receipt.policy_version().map(PolicyVersion::value),
        propagation: WriteOutcomeMapper::propagation(&receipt),
    })
}
