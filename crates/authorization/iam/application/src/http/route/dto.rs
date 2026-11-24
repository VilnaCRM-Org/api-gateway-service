//! Wire shapes of the routes of the IAM context.
//!
//! Each one keeps its schema constraints and its validator attributes on the same field so that
//! both stay equal. The domain checks every value and reports all violations together; the wire
//! shapes name the limits in their schema.

use iam_domain::{
    CorsDraft, CorsPolicy, EnforcementMode, EntityVersion, HttpMethod, RatePolicyId, RetryPolicy,
    RouteDraft, RouteFlags, RouteHost, RouteId, RouteParts, ServiceName, UpstreamId,
};
use serde::{Deserialize, Deserializer, Serialize};
use shared_application::http::Violation;
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::command::update_route::{CorsChange, RoutePatch};
use crate::error::IamError;
use crate::http::dto::DEFAULT_PAGE_SIZE;
use crate::query::list_routes::{ListRoutesQuery, RoutePage};

/// The default largest request body of a route, in bytes: 1 MiB.
pub const DEFAULT_BODY_LIMIT_BYTES: i64 = 1_048_576;
/// The default request timeout of a route, in milliseconds.
pub const DEFAULT_REQUEST_TIMEOUT_MS: i64 = 30_000;
/// The default idle timeout of a route, in milliseconds.
pub const DEFAULT_IDLE_TIMEOUT_MS: i64 = 60_000;
/// The default `maxAgeSeconds` of a CORS policy.
pub const DEFAULT_CORS_MAX_AGE_SECONDS: i64 = 600;

/// An HTTP method that a route serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "UPPERCASE")]
#[schema(as = RouteMethod)]
pub enum HttpMethodDto {
    /// `GET`.
    Get,
    /// `HEAD`.
    Head,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `PATCH`.
    Patch,
    /// `DELETE`.
    Delete,
    /// `OPTIONS`.
    Options,
}

impl From<HttpMethodDto> for HttpMethod {
    fn from(method: HttpMethodDto) -> Self {
        match method {
            HttpMethodDto::Get => Self::Get,
            HttpMethodDto::Head => Self::Head,
            HttpMethodDto::Post => Self::Post,
            HttpMethodDto::Put => Self::Put,
            HttpMethodDto::Patch => Self::Patch,
            HttpMethodDto::Delete => Self::Delete,
            HttpMethodDto::Options => Self::Options,
        }
    }
}

impl From<HttpMethod> for HttpMethodDto {
    fn from(method: HttpMethod) -> Self {
        match method {
            HttpMethod::Get => Self::Get,
            HttpMethod::Head => Self::Head,
            HttpMethod::Post => Self::Post,
            HttpMethod::Put => Self::Put,
            HttpMethod::Patch => Self::Patch,
            HttpMethod::Delete => Self::Delete,
            HttpMethod::Options => Self::Options,
        }
    }
}

/// What the gateway does with a request that the decision denies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
#[schema(as = RouteEnforcement)]
pub enum EnforcementDto {
    /// A denied request is refused.
    Enforce,
    /// A denied request is let through and audited.
    Audit,
}

impl From<EnforcementDto> for EnforcementMode {
    fn from(mode: EnforcementDto) -> Self {
        match mode {
            EnforcementDto::Enforce => Self::Enforce,
            EnforcementDto::Audit => Self::Audit,
        }
    }
}

impl From<EnforcementMode> for EnforcementDto {
    fn from(mode: EnforcementMode) -> Self {
        match mode {
            EnforcementMode::Enforce => Self::Enforce,
            EnforcementMode::Audit => Self::Audit,
        }
    }
}

/// Which failed requests the gateway retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
#[schema(as = RouteRetryPolicy)]
pub enum RetryPolicyDto {
    /// Nothing is retried.
    None,
    /// Idempotent requests are retried.
    Idempotent,
}

impl From<RetryPolicyDto> for RetryPolicy {
    fn from(policy: RetryPolicyDto) -> Self {
        match policy {
            RetryPolicyDto::None => Self::None,
            RetryPolicyDto::Idempotent => Self::Idempotent,
        }
    }
}

impl From<RetryPolicy> for RetryPolicyDto {
    fn from(policy: RetryPolicy) -> Self {
        match policy {
            RetryPolicy::None => Self::None,
            RetryPolicy::Idempotent => Self::Idempotent,
        }
    }
}

pub(crate) const fn default_enforcement() -> EnforcementDto {
    EnforcementDto::Enforce
}

pub(crate) const fn default_retry_policy() -> RetryPolicyDto {
    RetryPolicyDto::None
}

pub(crate) const fn default_body_limit_bytes() -> i64 {
    DEFAULT_BODY_LIMIT_BYTES
}

pub(crate) const fn default_request_timeout_ms() -> i64 {
    DEFAULT_REQUEST_TIMEOUT_MS
}

pub(crate) const fn default_idle_timeout_ms() -> i64 {
    DEFAULT_IDLE_TIMEOUT_MS
}

const fn default_cors_max_age_seconds() -> i64 {
    DEFAULT_CORS_MAX_AGE_SECONDS
}

/// The CORS policy of a route: exact origins, never a wildcard.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(as = RouteCorsPolicy)]
pub struct CorsPolicyDto {
    /// The allowed origins, each an exact `https` (or `http`) origin such as
    /// `https://app.example.com`.
    #[schema(min_items = 1)]
    pub origins: Vec<String>,
    /// The allowed methods.
    #[serde(default)]
    pub methods: Vec<HttpMethodDto>,
    /// The allowed request headers.
    #[serde(default)]
    pub headers: Vec<String>,
    /// Whether credentials are allowed.
    #[serde(default)]
    #[schema(default = false)]
    pub allow_credentials: bool,
    /// How long a preflight answer may be cached, in seconds, at most 86,400.
    #[serde(default = "default_cors_max_age_seconds")]
    #[schema(minimum = 0, maximum = 86400, default = 600)]
    pub max_age_seconds: i64,
}

impl From<CorsPolicyDto> for CorsDraft {
    fn from(cors: CorsPolicyDto) -> Self {
        Self {
            origins: cors.origins,
            methods: cors.methods.into_iter().map(HttpMethod::from).collect(),
            headers: cors.headers,
            allow_credentials: cors.allow_credentials,
            max_age_seconds: cors.max_age_seconds,
        }
    }
}

impl From<&CorsPolicy> for CorsPolicyDto {
    fn from(cors: &CorsPolicy) -> Self {
        Self {
            origins: cors.origins().to_vec(),
            methods: cors
                .methods()
                .iter()
                .copied()
                .map(HttpMethodDto::from)
                .collect(),
            headers: cors.headers().to_vec(),
            allow_credentials: cors.allow_credentials(),
            max_age_seconds: i64::from(cors.max_age_seconds()),
        }
    }
}

/// The identifier of an entry that a request names, as a violation of `property_path` when it is
/// not a UUID.
fn violation_of_uuid(property_path: &str) -> IamError {
    IamError::Invalid(vec![Violation {
        property_path: property_path.to_owned(),
        message: "This value is not a valid UUID.".to_owned(),
        code: "uuid".to_owned(),
    }])
}

/// The upstream a request names.
fn upstream_of(text: &str) -> Result<UpstreamId, IamError> {
    UpstreamId::parse(text).map_err(|_error| violation_of_uuid("upstreamId"))
}

/// The rate policies a request names, in order.
fn rate_policies_of(texts: &[String]) -> Result<Vec<RatePolicyId>, IamError> {
    texts
        .iter()
        .map(|text| RatePolicyId::parse(text).map_err(|_error| violation_of_uuid("ratePolicyIds")))
        .collect()
}

/// Body of the route-creation operation.
#[derive(Debug, Clone, Deserialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(as = CreateRouteRequest)]
pub struct CreateRouteRequest {
    /// The lower-case DNS name of the host the route serves.
    #[schema(min_length = 1, max_length = 253, example = "app.example.test")]
    #[validate(length(
        min = 1,
        max = 253,
        message = "This value must contain between 1 and 253 characters."
    ))]
    pub host: String,
    /// The methods the route serves.
    #[schema(min_items = 1)]
    pub methods: Vec<HttpMethodDto>,
    /// The path pattern, with `{name}` and `{name:*}` segments.
    #[schema(min_length = 1, max_length = 2048, example = "/api/orders/{id}")]
    #[validate(length(
        min = 1,
        max = 2048,
        message = "This value must contain between 1 and 2048 characters."
    ))]
    pub path_pattern: String,
    /// The catalogue service whose keys authorize the route; it must equal the catalogue service
    /// of the upstream.
    #[schema(min_length = 1, max_length = 63, example = "core")]
    #[validate(length(
        min = 1,
        max = 63,
        message = "This value must contain between 1 and 63 characters."
    ))]
    pub service: String,
    /// The upstream the route forwards to.
    #[schema(format = Uuid)]
    pub upstream_id: String,
    /// Whether the route serves GraphQL; `false` when absent.
    #[serde(default)]
    #[schema(default = false)]
    pub graphql: Option<bool>,
    /// Whether the route streams its response; `false` when absent.
    #[serde(default)]
    #[schema(default = false)]
    pub streaming: Option<bool>,
    /// Whether the route is served without authentication; needs `iam:route:anonymous`; `false`
    /// when absent.
    #[serde(default)]
    #[schema(default = false)]
    pub anonymous: Option<bool>,
    /// The enforcement mode; `audit` needs `iam:route:anonymous`.
    #[serde(default = "default_enforcement")]
    pub enforcement: EnforcementDto,
    /// The largest request body, in bytes.
    #[serde(default = "default_body_limit_bytes")]
    #[schema(minimum = 1, default = 1_048_576)]
    pub body_limit_bytes: i64,
    /// The request timeout, in milliseconds.
    #[serde(default = "default_request_timeout_ms")]
    #[schema(minimum = 1, default = 30000)]
    pub request_timeout_ms: i64,
    /// The idle timeout, in milliseconds.
    #[serde(default = "default_idle_timeout_ms")]
    #[schema(minimum = 1, default = 60000)]
    pub idle_timeout_ms: i64,
    /// Which failed requests are retried.
    #[serde(default = "default_retry_policy")]
    pub retry_policy: RetryPolicyDto,
    /// The rate policies of the route, in the order they apply, at most 10.
    #[serde(default)]
    #[schema(max_items = 10)]
    pub rate_policy_ids: Vec<String>,
    /// The CORS policy of the route, when it has one.
    #[serde(default)]
    pub cors: Option<CorsPolicyDto>,
}

impl CreateRouteRequest {
    /// The text that the idempotency digest of the request covers: the operation and the fields,
    /// so that a different body under the same key is a different request.
    #[must_use]
    pub fn canonical_form(&self) -> String {
        format!("route.create:{self:?}")
    }

    /// The draft that the request asks for.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with a violation of `upstreamId` or `ratePolicyIds` when an
    /// identifier is not a UUID.
    pub fn into_draft(self) -> Result<RouteDraft, IamError> {
        Ok(RouteDraft {
            host: self.host,
            methods: self.methods.into_iter().map(HttpMethod::from).collect(),
            path_pattern: self.path_pattern,
            service: self.service,
            upstream_id: upstream_of(&self.upstream_id)?,
            flags: RouteFlags::default()
                .with(
                    iam_domain::RouteFlag::Graphql,
                    self.graphql.unwrap_or(false),
                )
                .with(
                    iam_domain::RouteFlag::Streaming,
                    self.streaming.unwrap_or(false),
                )
                .with(
                    iam_domain::RouteFlag::Anonymous,
                    self.anonymous.unwrap_or(false),
                ),
            enforcement: self.enforcement.into(),
            body_limit: self.body_limit_bytes,
            request_timeout_ms: self.request_timeout_ms,
            idle_timeout_ms: self.idle_timeout_ms,
            retry: self.retry_policy.into(),
            rate_policies: rate_policies_of(&self.rate_policy_ids)?,
            cors: self.cors.map(CorsDraft::from),
        })
    }
}

/// What the body of an update says about the CORS policy: nothing, `null` or a policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CorsUpdate {
    /// The member is absent: the stored policy stays.
    #[default]
    Keep,
    /// The member is `null`: the policy is removed.
    Remove,
    /// The member holds a policy: it replaces the stored one.
    Set(CorsPolicyDto),
}

/// The CORS member of an update: `null` removes the policy, a value replaces it.
fn cors_update<'de, D: Deserializer<'de>>(deserializer: D) -> Result<CorsUpdate, D::Error> {
    Option::<CorsPolicyDto>::deserialize(deserializer)
        .map(|cors| cors.map_or(CorsUpdate::Remove, CorsUpdate::Set))
}

/// Body of the route-update operation: every member is optional, and an absent one stays as it
/// is.
#[derive(Debug, Clone, Default, Deserialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(as = UpdateRouteRequest)]
pub struct UpdateRouteRequest {
    /// The lower-case DNS name of the host the route serves.
    #[schema(min_length = 1, max_length = 253, example = "app.example.test")]
    #[validate(length(
        min = 1,
        max = 253,
        message = "This value must contain between 1 and 253 characters."
    ))]
    pub host: Option<String>,
    /// The methods the route serves.
    #[schema(min_items = 1)]
    pub methods: Option<Vec<HttpMethodDto>>,
    /// The path pattern, with `{name}` and `{name:*}` segments.
    #[schema(min_length = 1, max_length = 2048, example = "/api/orders/{id}")]
    #[validate(length(
        min = 1,
        max = 2048,
        message = "This value must contain between 1 and 2048 characters."
    ))]
    pub path_pattern: Option<String>,
    /// The catalogue service whose keys authorize the route.
    #[schema(min_length = 1, max_length = 63, example = "core")]
    #[validate(length(
        min = 1,
        max = 63,
        message = "This value must contain between 1 and 63 characters."
    ))]
    pub service: Option<String>,
    /// The upstream the route forwards to.
    #[schema(format = Uuid)]
    pub upstream_id: Option<String>,
    /// Whether the route serves GraphQL.
    pub graphql: Option<bool>,
    /// Whether the route streams its response.
    pub streaming: Option<bool>,
    /// Whether the route is served without authentication; changing it needs
    /// `iam:route:anonymous`.
    pub anonymous: Option<bool>,
    /// The enforcement mode; changing it needs `iam:route:anonymous`.
    pub enforcement: Option<EnforcementDto>,
    /// The largest request body, in bytes.
    #[schema(minimum = 1)]
    pub body_limit_bytes: Option<i64>,
    /// The request timeout, in milliseconds.
    #[schema(minimum = 1)]
    pub request_timeout_ms: Option<i64>,
    /// The idle timeout, in milliseconds.
    #[schema(minimum = 1)]
    pub idle_timeout_ms: Option<i64>,
    /// Which failed requests are retried.
    pub retry_policy: Option<RetryPolicyDto>,
    /// The rate policies of the route, in the order they apply, at most 10.
    #[schema(max_items = 10)]
    pub rate_policy_ids: Option<Vec<String>>,
    /// The CORS policy of the route; `null` removes it.
    #[serde(default, deserialize_with = "cors_update")]
    #[schema(value_type = Option<CorsPolicyDto>, nullable = true)]
    pub cors: CorsUpdate,
}

impl UpdateRouteRequest {
    /// The text that the idempotency digest covers: the operation, the route, the version and the
    /// fields.
    #[must_use]
    pub fn canonical_form(&self, id: RouteId, expected: EntityVersion) -> String {
        format!(
            "route.update:{:?}",
            (id.to_string(), expected.value(), self)
        )
    }

    /// The patch that the request asks for.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with a violation of `upstreamId` or `ratePolicyIds` when an
    /// identifier is not a UUID.
    pub fn into_patch(self) -> Result<RoutePatch, IamError> {
        Ok(RoutePatch {
            host: self.host,
            methods: self
                .methods
                .map(|methods| methods.into_iter().map(HttpMethod::from).collect()),
            path_pattern: self.path_pattern,
            service: self.service,
            upstream_id: self.upstream_id.as_deref().map(upstream_of).transpose()?,
            graphql: self.graphql,
            streaming: self.streaming,
            anonymous: self.anonymous,
            enforcement: self.enforcement.map(EnforcementMode::from),
            body_limit: self.body_limit_bytes,
            request_timeout_ms: self.request_timeout_ms,
            idle_timeout_ms: self.idle_timeout_ms,
            retry: self.retry_policy.map(RetryPolicy::from),
            rate_policies: self
                .rate_policy_ids
                .as_deref()
                .map(rate_policies_of)
                .transpose()?,
            cors: match self.cors {
                CorsUpdate::Keep => CorsChange::Keep,
                CorsUpdate::Remove => CorsChange::Remove,
                CorsUpdate::Set(cors) => CorsChange::Set(CorsDraft::from(cors)),
            },
        })
    }
}

/// The text that the idempotency digest of a route deletion covers: the operation, the route and
/// the version.
#[must_use]
pub fn delete_route_canonical_form(id: RouteId, expected: EntityVersion) -> String {
    format!("route.delete:{:?}", (id.to_string(), expected.value()))
}

/// How the gateway carries the traffic of a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = RouteTraffic)]
pub struct RouteTrafficDto {
    /// Whether the route serves GraphQL.
    pub graphql: bool,
    /// Whether the route streams its response.
    pub streaming: bool,
}

/// A route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = Route)]
pub struct RouteResponse {
    /// The identifier of the route.
    #[schema(format = Uuid)]
    pub id: String,
    /// The host the route serves.
    pub host: String,
    /// The methods the route serves.
    pub methods: Vec<HttpMethodDto>,
    /// The path pattern.
    pub path_pattern: String,
    /// The catalogue service whose keys authorize the route.
    pub service: String,
    /// The upstream the route forwards to.
    #[schema(format = Uuid)]
    pub upstream_id: String,
    /// Whether the route serves GraphQL and whether it streams its response.
    #[serde(flatten)]
    pub traffic: RouteTrafficDto,
    /// Whether the route is served without authentication.
    pub anonymous: bool,
    /// The enforcement mode.
    pub enforcement: EnforcementDto,
    /// The largest request body, in bytes.
    #[schema(minimum = 1)]
    pub body_limit_bytes: u64,
    /// The request timeout, in milliseconds.
    #[schema(minimum = 1)]
    pub request_timeout_ms: u32,
    /// The idle timeout, in milliseconds.
    #[schema(minimum = 1)]
    pub idle_timeout_ms: u32,
    /// Which failed requests are retried.
    pub retry_policy: RetryPolicyDto,
    /// The rate policies of the route, in the order they apply.
    pub rate_policy_ids: Vec<String>,
    /// The CORS policy of the route, when it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cors: Option<CorsPolicyDto>,
    /// Whether IAM manages the route itself; the API refuses every change of a system route.
    pub system: bool,
    /// The version of the route; its `ETag` is this number in double quotes.
    #[schema(minimum = 1)]
    pub version: i64,
    /// When the route was created, as an RFC 3339 UTC time.
    #[schema(format = DateTime, example = "2026-11-23T10:15:30.123456Z")]
    pub created_at: String,
    /// When the route was last changed, as an RFC 3339 UTC time.
    #[schema(format = DateTime, example = "2026-11-23T10:15:30.123456Z")]
    pub updated_at: String,
}

impl From<RouteParts> for RouteResponse {
    fn from(route: RouteParts) -> Self {
        let fields = &route.fields;
        let flags = fields.flags();
        Self {
            id: route.id.to_string(),
            host: fields.host().to_string(),
            methods: fields
                .methods()
                .iter()
                .copied()
                .map(HttpMethodDto::from)
                .collect(),
            path_pattern: fields.path_pattern().to_string(),
            service: fields.service().to_string(),
            upstream_id: fields.upstream_id().to_string(),
            traffic: RouteTrafficDto {
                graphql: flags.graphql(),
                streaming: flags.streaming(),
            },
            anonymous: flags.anonymous(),
            enforcement: EnforcementDto::from(fields.enforcement()),
            body_limit_bytes: fields.body_limit().bytes(),
            request_timeout_ms: fields.timeouts().request_ms(),
            idle_timeout_ms: fields.timeouts().idle_ms(),
            retry_policy: RetryPolicyDto::from(fields.retry()),
            rate_policy_ids: fields
                .rate_policies()
                .iter()
                .map(ToString::to_string)
                .collect(),
            cors: fields.cors().map(CorsPolicyDto::from),
            system: route.system,
            version: route.version.value(),
            created_at: humantime::format_rfc3339_micros(route.created_at).to_string(),
            updated_at: humantime::format_rfc3339_micros(route.updated_at).to_string(),
        }
    }
}

/// One page of routes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = RoutePage)]
pub struct RoutePageResponse {
    /// The routes of the page.
    pub items: Vec<RouteResponse>,
    /// The `after` value of the next page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(format = Uuid)]
    pub next_cursor: Option<String>,
}

impl From<RoutePage> for RoutePageResponse {
    fn from(page: RoutePage) -> Self {
        Self {
            items: page.routes.into_iter().map(RouteResponse::from).collect(),
            next_cursor: page.next_after.map(|id| id.to_string()),
        }
    }
}

/// Query parameters of the route list; `limit` is signed so that a negative value is a 422, not a
/// parse error.
#[derive(Debug, Clone, Deserialize, IntoParams, Validate)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ListRoutesParams {
    /// The largest number of routes of the page.
    #[param(minimum = 1, maximum = 100, default = 30)]
    #[validate(range(min = 1, max = 100, message = "This value must be between 1 and 100."))]
    pub limit: i32,
    /// The `nextCursor` of the previous page; absent for the first page.
    #[param(format = Uuid)]
    pub after: Option<String>,
    /// Only the routes of this host.
    pub host: Option<String>,
    /// Only the routes that forward to this upstream.
    #[param(format = Uuid)]
    pub upstream: Option<String>,
    /// Only the routes of this catalogue service.
    pub service: Option<String>,
}

impl Default for ListRoutesParams {
    fn default() -> Self {
        Self {
            limit: DEFAULT_PAGE_SIZE,
            after: None,
            host: None,
            upstream: None,
            service: None,
        }
    }
}

impl ListRoutesParams {
    /// The query for these parameters; call it after validation, which makes `limit` positive.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with a violation of `after`, `host`, `upstream` or `service` when the
    /// value is not valid.
    pub fn into_query(self) -> Result<ListRoutesQuery, IamError> {
        let after = self
            .after
            .as_deref()
            .map(RouteId::parse)
            .transpose()
            .map_err(|_error| violation_of_uuid("after"))?;
        let host = self
            .host
            .as_deref()
            .map(RouteHost::new)
            .transpose()
            .map_err(|error| {
                IamError::invalid_property("host", &error.to_string(), error.code())
            })?;
        let upstream = self
            .upstream
            .as_deref()
            .map(UpstreamId::parse)
            .transpose()
            .map_err(|_error| violation_of_uuid("upstream"))?;
        let service = self
            .service
            .as_deref()
            .map(ServiceName::new)
            .transpose()
            .map_err(|error| {
                IamError::invalid_property("service", &error.to_string(), error.code())
            })?;
        Ok(ListRoutesQuery {
            limit: self.limit.unsigned_abs(),
            after,
            host,
            upstream,
            service,
        })
    }
}

#[cfg(test)]
mod tests;
