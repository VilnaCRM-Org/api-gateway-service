//! Wire shapes of the upstreams of the IAM context.
//!
//! Each one keeps its schema constraints and its validator attributes on the same field so that
//! both stay equal. The numeric limits are checked by the domain, which reports every violation of
//! the settings together; the wire shapes name them in their schema.

use iam_domain::{EntityVersion, UpstreamId, UpstreamParts, UpstreamProtocol};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::command::update_upstream::UpstreamPatch;
use crate::error::IamError;
use crate::http::dto::DEFAULT_PAGE_SIZE;
use crate::query::list_upstreams::{ListUpstreamsQuery, UpstreamPage};

/// The default connect timeout of an upstream, in milliseconds.
pub const DEFAULT_CONNECT_TIMEOUT_MS: i64 = 250;
/// The default response timeout of an upstream, in milliseconds.
pub const DEFAULT_RESPONSE_TIMEOUT_MS: i64 = 10_000;
/// The default largest number of concurrent requests to an upstream.
pub const DEFAULT_CONCURRENCY_LIMIT: i64 = 256;
/// The default retry budget of an upstream, in percent of the requests.
pub const DEFAULT_RETRY_BUDGET_PERCENT: i64 = 10;
/// The default number of consecutive failures after which an endpoint is ejected.
pub const DEFAULT_OUTLIER_CONSECUTIVE_ERRORS: i64 = 5;

/// The protocol the gateway speaks to an upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
#[schema(as = UpstreamProtocol)]
pub enum UpstreamProtocolDto {
    /// HTTP/1.1.
    Http1,
    /// HTTP/2 over cleartext.
    H2c,
}

impl From<UpstreamProtocolDto> for UpstreamProtocol {
    fn from(protocol: UpstreamProtocolDto) -> Self {
        match protocol {
            UpstreamProtocolDto::Http1 => Self::Http1,
            UpstreamProtocolDto::H2c => Self::H2c,
        }
    }
}

impl From<UpstreamProtocol> for UpstreamProtocolDto {
    fn from(protocol: UpstreamProtocol) -> Self {
        match protocol {
            UpstreamProtocol::Http1 => Self::Http1,
            UpstreamProtocol::H2c => Self::H2c,
        }
    }
}

const fn default_connect_timeout_ms() -> i64 {
    DEFAULT_CONNECT_TIMEOUT_MS
}

const fn default_response_timeout_ms() -> i64 {
    DEFAULT_RESPONSE_TIMEOUT_MS
}

const fn default_concurrency_limit() -> i64 {
    DEFAULT_CONCURRENCY_LIMIT
}

const fn default_retry_budget_percent() -> i64 {
    DEFAULT_RETRY_BUDGET_PERCENT
}

const fn default_outlier_consecutive_errors() -> i64 {
    DEFAULT_OUTLIER_CONSECUTIVE_ERRORS
}

/// Body of the upstream-creation operation.
#[derive(Debug, Clone, Deserialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(as = CreateUpstreamRequest)]
pub struct CreateUpstreamRequest {
    /// The name of the upstream: a service name such as `core`, unique among the upstreams that
    /// are not deleted; it cannot change afterwards.
    #[schema(min_length = 1, max_length = 63, example = "core")]
    #[validate(length(
        min = 1,
        max = 63,
        message = "This value must contain between 1 and 63 characters."
    ))]
    pub name: String,
    /// The Kubernetes namespace of the Service.
    #[schema(min_length = 1, max_length = 63, example = "platform")]
    #[validate(length(
        min = 1,
        max = 63,
        message = "This value must contain between 1 and 63 characters."
    ))]
    pub namespace: String,
    /// The Kubernetes Service that the gateway proxies to.
    #[schema(min_length = 1, max_length = 63, example = "core-service")]
    #[validate(length(
        min = 1,
        max = 63,
        message = "This value must contain between 1 and 63 characters."
    ))]
    pub service: String,
    /// The catalogue service whose keys authorize the routes of this upstream.
    #[schema(min_length = 1, max_length = 63, example = "core")]
    #[validate(length(
        min = 1,
        max = 63,
        message = "This value must contain between 1 and 63 characters."
    ))]
    pub catalog_service: String,
    /// Whether the credentials of the caller are forwarded to the upstream.
    #[serde(default)]
    #[schema(default = false)]
    pub forward_credentials: bool,
    /// The port of the Service.
    #[schema(minimum = 1, maximum = 65535, example = 8080)]
    pub port: i64,
    /// The protocol the gateway speaks to the upstream.
    pub protocol: UpstreamProtocolDto,
    /// The connect timeout, in milliseconds.
    #[serde(default = "default_connect_timeout_ms")]
    #[schema(minimum = 1, default = 250)]
    pub connect_timeout_ms: i64,
    /// The response timeout, in milliseconds.
    #[serde(default = "default_response_timeout_ms")]
    #[schema(minimum = 1, default = 10000)]
    pub response_timeout_ms: i64,
    /// The largest number of concurrent requests to the upstream.
    #[serde(default = "default_concurrency_limit")]
    #[schema(minimum = 1, default = 256)]
    pub concurrency_limit: i64,
    /// The retry budget, in percent of the requests.
    #[serde(default = "default_retry_budget_percent")]
    #[schema(minimum = 0, maximum = 100, default = 10)]
    pub retry_budget_percent: i64,
    /// The number of consecutive failures after which an endpoint is ejected.
    #[serde(default = "default_outlier_consecutive_errors")]
    #[schema(minimum = 1, default = 5)]
    pub outlier_consecutive_errors: i64,
}

impl CreateUpstreamRequest {
    /// The text that the idempotency digest of the request covers: the operation and the fields,
    /// so that a different body under the same key is a different request.
    #[must_use]
    pub fn canonical_form(&self) -> String {
        format!("upstream.create:{self:?}")
    }
}

/// Body of the upstream-update operation: every member is optional, and an absent one stays as
/// it is. The name cannot change: a name other than the stored one is a violation.
#[derive(Debug, Clone, Default, Deserialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(as = UpdateUpstreamRequest)]
pub struct UpdateUpstreamRequest {
    /// The name of the upstream; it must equal the stored name.
    #[schema(min_length = 1, max_length = 63, example = "core")]
    #[validate(length(
        min = 1,
        max = 63,
        message = "This value must contain between 1 and 63 characters."
    ))]
    pub name: Option<String>,
    /// The Kubernetes namespace of the Service.
    #[schema(min_length = 1, max_length = 63, example = "platform")]
    #[validate(length(
        min = 1,
        max = 63,
        message = "This value must contain between 1 and 63 characters."
    ))]
    pub namespace: Option<String>,
    /// The Kubernetes Service that the gateway proxies to.
    #[schema(min_length = 1, max_length = 63, example = "core-service")]
    #[validate(length(
        min = 1,
        max = 63,
        message = "This value must contain between 1 and 63 characters."
    ))]
    pub service: Option<String>,
    /// The catalogue service whose keys authorize the routes of this upstream.
    #[schema(min_length = 1, max_length = 63, example = "core")]
    #[validate(length(
        min = 1,
        max = 63,
        message = "This value must contain between 1 and 63 characters."
    ))]
    pub catalog_service: Option<String>,
    /// Whether the credentials of the caller are forwarded to the upstream.
    pub forward_credentials: Option<bool>,
    /// The port of the Service.
    #[schema(minimum = 1, maximum = 65535, example = 8080)]
    pub port: Option<i64>,
    /// The protocol the gateway speaks to the upstream.
    pub protocol: Option<UpstreamProtocolDto>,
    /// The connect timeout, in milliseconds.
    #[schema(minimum = 1)]
    pub connect_timeout_ms: Option<i64>,
    /// The response timeout, in milliseconds.
    #[schema(minimum = 1)]
    pub response_timeout_ms: Option<i64>,
    /// The largest number of concurrent requests to the upstream.
    #[schema(minimum = 1)]
    pub concurrency_limit: Option<i64>,
    /// The retry budget, in percent of the requests.
    #[schema(minimum = 0, maximum = 100)]
    pub retry_budget_percent: Option<i64>,
    /// The number of consecutive failures after which an endpoint is ejected.
    #[schema(minimum = 1)]
    pub outlier_consecutive_errors: Option<i64>,
}

impl UpdateUpstreamRequest {
    /// The text that the idempotency digest covers: the operation, the upstream, the version and
    /// the fields.
    #[must_use]
    pub fn canonical_form(&self, id: UpstreamId, expected: EntityVersion) -> String {
        format!(
            "upstream.update:{:?}",
            (id.to_string(), expected.value(), self)
        )
    }

    /// The patch that the request asks for.
    #[must_use]
    pub fn into_patch(self) -> UpstreamPatch {
        UpstreamPatch {
            name: self.name,
            namespace: self.namespace,
            service_name: self.service,
            catalog_service: self.catalog_service,
            port: self.port,
            protocol: self.protocol.map(UpstreamProtocol::from),
            forward_credentials: self.forward_credentials,
            connect_timeout_ms: self.connect_timeout_ms,
            response_timeout_ms: self.response_timeout_ms,
            concurrency_limit: self.concurrency_limit,
            retry_budget_percent: self.retry_budget_percent,
            outlier_threshold: self.outlier_consecutive_errors,
        }
    }
}

/// The text that the idempotency digest of an upstream deletion covers: the operation, the upstream
/// and the version.
#[must_use]
pub fn delete_upstream_canonical_form(id: UpstreamId, expected: EntityVersion) -> String {
    format!("upstream.delete:{:?}", (id.to_string(), expected.value()))
}

/// An upstream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = Upstream)]
pub struct UpstreamResponse {
    /// The identifier of the upstream.
    #[schema(format = Uuid)]
    pub id: String,
    /// The name of the upstream.
    #[schema(min_length = 1, max_length = 63)]
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
    #[schema(minimum = 1, maximum = 65535)]
    pub port: u16,
    /// The protocol the gateway speaks to the upstream.
    pub protocol: UpstreamProtocolDto,
    /// The connect timeout, in milliseconds.
    #[schema(minimum = 1)]
    pub connect_timeout_ms: u32,
    /// The response timeout, in milliseconds.
    #[schema(minimum = 1)]
    pub response_timeout_ms: u32,
    /// The largest number of concurrent requests to the upstream.
    #[schema(minimum = 1)]
    pub concurrency_limit: u32,
    /// The retry budget, in percent of the requests.
    #[schema(minimum = 0, maximum = 100)]
    pub retry_budget_percent: u8,
    /// The number of consecutive failures after which an endpoint is ejected.
    #[schema(minimum = 1)]
    pub outlier_consecutive_errors: u32,
    /// Whether IAM manages the upstream itself; the API refuses every change of a system upstream.
    pub system: bool,
    /// The version of the upstream; its `ETag` is this number in double quotes.
    #[schema(minimum = 1)]
    pub version: i64,
    /// When the upstream was created, as an RFC 3339 UTC time.
    #[schema(format = DateTime, example = "2026-11-23T10:15:30.123456Z")]
    pub created_at: String,
    /// When the upstream was last changed, as an RFC 3339 UTC time.
    #[schema(format = DateTime, example = "2026-11-23T10:15:30.123456Z")]
    pub updated_at: String,
}

impl From<UpstreamParts> for UpstreamResponse {
    fn from(upstream: UpstreamParts) -> Self {
        let settings = &upstream.settings;
        Self {
            id: upstream.id.to_string(),
            name: upstream.name.to_string(),
            namespace: settings.namespace().to_owned(),
            service: settings.service_name().to_owned(),
            catalog_service: settings.catalog_service().to_string(),
            forward_credentials: settings.forward_credentials(),
            port: settings.port(),
            protocol: UpstreamProtocolDto::from(settings.protocol()),
            connect_timeout_ms: settings.connect_timeout_ms(),
            response_timeout_ms: settings.response_timeout_ms(),
            concurrency_limit: settings.concurrency_limit(),
            retry_budget_percent: settings.retry_budget_percent(),
            outlier_consecutive_errors: settings.outlier_threshold(),
            system: upstream.system,
            version: upstream.version.value(),
            created_at: humantime::format_rfc3339_micros(upstream.created_at).to_string(),
            updated_at: humantime::format_rfc3339_micros(upstream.updated_at).to_string(),
        }
    }
}

/// One page of upstreams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = UpstreamPage)]
pub struct UpstreamPageResponse {
    /// The upstreams of the page.
    pub items: Vec<UpstreamResponse>,
    /// The `after` value of the next page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(format = Uuid)]
    pub next_cursor: Option<String>,
}

impl From<UpstreamPage> for UpstreamPageResponse {
    fn from(page: UpstreamPage) -> Self {
        Self {
            items: page
                .upstreams
                .into_iter()
                .map(UpstreamResponse::from)
                .collect(),
            next_cursor: page.next_after.map(|id| id.to_string()),
        }
    }
}

/// Query parameters of the upstream list; `limit` is signed so that a negative value is a 422, not
/// a parse error.
#[derive(Debug, Clone, Deserialize, IntoParams, Validate)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ListUpstreamsParams {
    /// The largest number of upstreams of the page.
    #[param(minimum = 1, maximum = 100, default = 30)]
    #[validate(range(min = 1, max = 100, message = "This value must be between 1 and 100."))]
    pub limit: i32,
    /// The `nextCursor` of the previous page; absent for the first page.
    #[param(format = Uuid)]
    pub after: Option<String>,
}

impl Default for ListUpstreamsParams {
    fn default() -> Self {
        Self {
            limit: DEFAULT_PAGE_SIZE,
            after: None,
        }
    }
}

impl ListUpstreamsParams {
    /// The query for these parameters; call it after validation, which makes `limit` positive.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with a violation of `after` when it is not a UUID.
    pub fn into_query(self) -> Result<ListUpstreamsQuery, IamError> {
        let after = self
            .after
            .as_deref()
            .map(UpstreamId::parse)
            .transpose()
            .map_err(|_error| {
                IamError::invalid_property("after", "This value is not a valid UUID.", "uuid")
            })?;
        Ok(ListUpstreamsQuery {
            limit: self.limit.unsigned_abs(),
            after,
        })
    }
}

#[cfg(test)]
mod tests;
