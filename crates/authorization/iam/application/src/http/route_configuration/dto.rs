//! Wire shapes of the declarative route configuration of a host (FR-58).
//!
//! A declared route is the route of the creation operation without its host, which the path of the
//! operation names. The domain checks every value and reports all violations together, with the
//! position of the route in the set.

use iam_domain::{RouteChangeClass, RouteDraft, RouteFields, RouteParts};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::command::route_configuration_plan::indexed;
use crate::error::IamError;
use crate::http::route::dto::{
    CorsPolicyDto, CreateRouteRequest, EnforcementDto, HttpMethodDto, RetryPolicyDto,
    RouteResponse, default_body_limit_bytes, default_enforcement, default_idle_timeout_ms,
    default_request_timeout_ms, default_retry_policy,
};
use crate::query::get_route_configuration::RouteConfiguration;
use crate::query::preview_route_configuration::RouteConfigurationPreview;

/// One route of a declared set.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(as = RouteDeclaration)]
pub struct RouteDeclarationDto {
    /// The methods the route serves.
    #[schema(min_items = 1)]
    pub methods: Vec<HttpMethodDto>,
    /// The path pattern, with `{name}` and `{name:*}` segments.
    #[schema(min_length = 1, max_length = 2048, example = "/api/orders/{id}")]
    pub path_pattern: String,
    /// The catalogue service whose keys authorize the route; it must equal the catalogue service
    /// of the upstream.
    #[schema(min_length = 1, max_length = 63, example = "core")]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cors: Option<CorsPolicyDto>,
}

impl RouteDeclarationDto {
    /// The draft that the declaration asks for; its host is empty, because the host of the
    /// operation replaces it.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with a violation of `upstreamId` or `ratePolicyIds` when an
    /// identifier is not a UUID.
    pub fn into_draft(self) -> Result<RouteDraft, IamError> {
        CreateRouteRequest {
            host: String::new(),
            methods: self.methods,
            path_pattern: self.path_pattern,
            service: self.service,
            upstream_id: self.upstream_id,
            graphql: self.graphql,
            streaming: self.streaming,
            anonymous: self.anonymous,
            enforcement: self.enforcement,
            body_limit_bytes: self.body_limit_bytes,
            request_timeout_ms: self.request_timeout_ms,
            idle_timeout_ms: self.idle_timeout_ms,
            retry_policy: self.retry_policy,
            rate_policy_ids: self.rate_policy_ids,
            cors: self.cors,
        }
        .into_draft()
    }
}

impl From<RouteParts> for RouteDeclarationDto {
    fn from(route: RouteParts) -> Self {
        let response = RouteResponse::from(route);
        Self {
            methods: response.methods,
            path_pattern: response.path_pattern,
            service: response.service,
            upstream_id: response.upstream_id,
            graphql: Some(response.traffic.graphql),
            streaming: Some(response.traffic.streaming),
            anonymous: Some(response.anonymous),
            enforcement: response.enforcement,
            body_limit_bytes: i64::try_from(response.body_limit_bytes).unwrap_or(i64::MAX),
            request_timeout_ms: i64::from(response.request_timeout_ms),
            idle_timeout_ms: i64::from(response.idle_timeout_ms),
            retry_policy: response.retry_policy,
            rate_policy_ids: response.rate_policy_ids,
            cors: response.cors,
        }
    }
}

/// Body of the route-configuration operation: the full route set of the host.
#[derive(Debug, Clone, Deserialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(as = ApplyRouteConfigurationRequest)]
pub struct ApplyRouteConfigurationRequest {
    /// The routes the host has afterwards, at most `ROUTE_CONFIGURATION_MAX_ROUTES` (1,000 by
    /// default); a stored route that the set does not declare is deleted.
    pub routes: Vec<RouteDeclarationDto>,
}

impl ApplyRouteConfigurationRequest {
    /// The drafts of the declared routes.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with a violation of `routes[<index>].upstreamId` or
    /// `routes[<index>].ratePolicyIds` for the first route with an identifier that is not a
    /// UUID.
    pub fn into_drafts(self) -> Result<Vec<RouteDraft>, IamError> {
        self.routes
            .into_iter()
            .enumerate()
            .map(|(index, route)| route.into_draft().map_err(|error| indexed(index, error)))
            .collect()
    }
}

/// Query parameters of the route-configuration operation.
#[derive(Debug, Clone, Default, Deserialize, IntoParams, Validate)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ApplyRouteConfigurationParams {
    /// Returns the diff and writes nothing; `false` when absent.
    #[param(default = false)]
    pub dry_run: bool,
}

/// The routes of a host and the version of the set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = RouteConfiguration)]
pub struct RouteConfigurationResponse {
    /// The host.
    pub host: String,
    /// The version of the set; its `ETag` is this number in double quotes.
    #[schema(minimum = 1)]
    pub version: i64,
    /// The routes of the host, in the form that the operation accepts.
    pub routes: Vec<RouteDeclarationDto>,
}

impl From<RouteConfiguration> for RouteConfigurationResponse {
    fn from(configuration: RouteConfiguration) -> Self {
        Self {
            host: configuration.host.to_string(),
            version: configuration.version.value(),
            routes: configuration
                .routes
                .into_iter()
                .map(RouteDeclarationDto::from)
                .collect(),
        }
    }
}

/// A route that a set adds, changes or removes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = RouteConfigurationChange)]
pub struct RouteChangeDto {
    /// The methods of the route.
    pub methods: Vec<HttpMethodDto>,
    /// The path pattern of the route.
    pub path_pattern: String,
    /// The names of the properties that change; present for a changed route only.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub changed_fields: Vec<String>,
}

/// The routes that a set adds, changes and removes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = RouteConfigurationDiff)]
pub struct RouteConfigurationDiffResponse {
    /// The host.
    pub host: String,
    /// Whether the request was a dry run, which wrote nothing.
    pub dry_run: bool,
    /// The version of the set of the host: the version after an applied set, the stored version
    /// after a dry run or a set that changes nothing.
    #[schema(minimum = 1)]
    pub version: i64,
    /// The number of routes the host has, or would have after a dry run.
    pub route_count: u64,
    /// Whether the diff deletes a route, clears `anonymous` or moves `enforcement` from `audit`
    /// to `enforce`, which makes the application revocation-class.
    pub revocation: bool,
    /// The number of declared routes that equal a stored route.
    pub unchanged: u64,
    /// The routes the set creates.
    pub added: Vec<RouteChangeDto>,
    /// The routes the set updates.
    pub changed: Vec<RouteChangeDto>,
    /// The routes the set deletes.
    pub removed: Vec<RouteChangeDto>,
}

impl RouteConfigurationDiffResponse {
    /// The response for `preview`: a dry run when `dry_run` is set, otherwise the applied set whose
    /// resulting version is `applied_version`, when the application committed a change.
    #[must_use]
    pub fn of(
        preview: &RouteConfigurationPreview,
        dry_run: bool,
        applied_version: Option<i64>,
    ) -> Self {
        let diff = &preview.diff;
        let entry = |fields: &RouteFields, changed: Vec<String>| RouteChangeDto {
            methods: fields
                .methods()
                .iter()
                .copied()
                .map(HttpMethodDto::from)
                .collect(),
            path_pattern: fields.path_pattern().to_string(),
            changed_fields: changed,
        };
        Self {
            host: preview.host.to_string(),
            dry_run,
            version: applied_version.unwrap_or_else(|| preview.version.value()),
            route_count: u64::try_from(preview.route_count).unwrap_or(u64::MAX),
            revocation: diff.class() == RouteChangeClass::Revocation,
            unchanged: u64::try_from(diff.unchanged()).unwrap_or(u64::MAX),
            added: diff
                .added()
                .iter()
                .map(|fields| entry(fields, Vec::new()))
                .collect(),
            changed: diff
                .changed()
                .iter()
                .map(|changed| {
                    entry(
                        &changed.after,
                        changed
                            .changed_fields()
                            .into_iter()
                            .map(str::to_owned)
                            .collect(),
                    )
                })
                .collect(),
            removed: diff
                .removed()
                .iter()
                .map(|route| entry(&route.fields, Vec::new()))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests;
