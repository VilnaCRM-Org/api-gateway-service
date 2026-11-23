//! The validated configuration of a route.

use std::collections::BTreeSet;

use crate::error::{InvalidIamValue, InvalidRoute};
use crate::route::cors::{CorsDraft, CorsPolicy};
use crate::route::settings::{BodyLimit, EnforcementMode, RetryPolicy, RouteFlags, RouteTimeouts};
use crate::value_object::http_method::HttpMethod;
use crate::value_object::identifier::{RatePolicyId, UpstreamId};
use crate::value_object::path_pattern::PathPattern;
use crate::value_object::route_host::RouteHost;
use crate::value_object::service_name::ServiceName;

/// The largest number of rate policies of a route.
const MAX_RATE_POLICIES: usize = 10;

/// The unvalidated values of a route, as a request carries them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDraft {
    /// The host.
    pub host: String,
    /// The methods the route serves.
    pub methods: Vec<HttpMethod>,
    /// The path pattern.
    pub path_pattern: String,
    /// The catalogue service the route belongs to.
    pub service: String,
    /// The upstream the route forwards to.
    pub upstream_id: UpstreamId,
    /// The flags.
    pub flags: RouteFlags,
    /// The enforcement mode.
    pub enforcement: EnforcementMode,
    /// The largest request body, in bytes.
    pub body_limit: i64,
    /// The request timeout, in milliseconds.
    pub request_timeout_ms: i64,
    /// The idle timeout, in milliseconds.
    pub idle_timeout_ms: i64,
    /// Which failed requests are retried.
    pub retry: RetryPolicy,
    /// The rate policies, in the order they apply.
    pub rate_policies: Vec<RatePolicyId>,
    /// The CORS policy, when the route has one.
    pub cors: Option<CorsDraft>,
}

/// The validated configuration of a route: everything an update can change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteFields {
    pub(super) host: RouteHost,
    pub(super) methods: Vec<HttpMethod>,
    pub(super) path_pattern: PathPattern,
    pub(super) service: ServiceName,
    pub(super) upstream_id: UpstreamId,
    pub(super) flags: RouteFlags,
    pub(super) enforcement: EnforcementMode,
    pub(super) body_limit: BodyLimit,
    pub(super) timeouts: RouteTimeouts,
    pub(super) retry: RetryPolicy,
    pub(super) rate_policies: Vec<RatePolicyId>,
    pub(super) cors: Option<CorsPolicy>,
}

impl RouteFields {
    /// Validates the draft.
    ///
    /// # Errors
    ///
    /// Every violation, in the order host, methods, path pattern, service, body limit, timeouts,
    /// rate policies, CORS policy.
    pub fn new(draft: &RouteDraft) -> Result<Self, Vec<InvalidRoute>> {
        let mut found = Vec::new();
        let target = target_of(draft, &mut found);
        let limits = limits_of(draft, &mut found);
        match (target, limits) {
            (
                Some((host, methods, path_pattern, service)),
                Some((body_limit, timeouts, rate_policies, cors)),
            ) => Ok(Self {
                host,
                methods,
                path_pattern,
                service,
                upstream_id: draft.upstream_id,
                flags: draft.flags,
                enforcement: draft.enforcement,
                body_limit,
                timeouts,
                retry: draft.retry,
                rate_policies,
                cors,
            }),
            _ => Err(found),
        }
    }

    /// The host.
    #[must_use]
    pub const fn host(&self) -> &RouteHost {
        &self.host
    }

    /// The methods, in order and without duplicates.
    #[must_use]
    pub fn methods(&self) -> &[HttpMethod] {
        &self.methods
    }

    /// The path pattern.
    #[must_use]
    pub const fn path_pattern(&self) -> &PathPattern {
        &self.path_pattern
    }

    /// The catalogue service the route belongs to.
    #[must_use]
    pub const fn service(&self) -> &ServiceName {
        &self.service
    }

    /// The upstream the route forwards to.
    #[must_use]
    pub const fn upstream_id(&self) -> UpstreamId {
        self.upstream_id
    }

    /// The flags.
    #[must_use]
    pub const fn flags(&self) -> RouteFlags {
        self.flags
    }

    /// The enforcement mode.
    #[must_use]
    pub const fn enforcement(&self) -> EnforcementMode {
        self.enforcement
    }

    /// The largest request body.
    #[must_use]
    pub const fn body_limit(&self) -> BodyLimit {
        self.body_limit
    }

    /// The timeouts.
    #[must_use]
    pub const fn timeouts(&self) -> RouteTimeouts {
        self.timeouts
    }

    /// Which failed requests are retried.
    #[must_use]
    pub const fn retry(&self) -> RetryPolicy {
        self.retry
    }

    /// The rate policies, in the order they apply.
    #[must_use]
    pub fn rate_policies(&self) -> &[RatePolicyId] {
        &self.rate_policies
    }

    /// The CORS policy, when the route has one.
    #[must_use]
    pub const fn cors(&self) -> Option<&CorsPolicy> {
        self.cors.as_ref()
    }

    /// Whether the two routes serve a method in common.
    #[must_use]
    pub fn shares_a_method_with(&self, other: &Self) -> bool {
        self.methods
            .iter()
            .any(|method| other.methods.contains(method))
    }

    /// The names of the properties in which `other` differs from this configuration.
    #[must_use]
    pub fn changed_fields(&self, other: &Self) -> Vec<&'static str> {
        [
            ("host", self.host != other.host),
            ("methods", self.methods != other.methods),
            ("pathPattern", self.path_pattern != other.path_pattern),
            ("service", self.service != other.service),
            ("upstreamId", self.upstream_id != other.upstream_id),
            ("graphql", self.flags.graphql() != other.flags.graphql()),
            (
                "streaming",
                self.flags.streaming() != other.flags.streaming(),
            ),
            (
                "anonymous",
                self.flags.anonymous() != other.flags.anonymous(),
            ),
            ("enforcement", self.enforcement != other.enforcement),
            ("bodyLimit", self.body_limit != other.body_limit),
            ("timeouts", self.timeouts != other.timeouts),
            ("retry", self.retry != other.retry),
            ("ratePolicies", self.rate_policies != other.rate_policies),
            ("cors", self.cors != other.cors),
        ]
        .into_iter()
        .filter_map(|(name, changed)| changed.then_some(name))
        .collect()
    }
}

/// What a route matches: the host, the methods, the path pattern and the service.
type Target = (RouteHost, Vec<HttpMethod>, PathPattern, ServiceName);

/// What a route enforces: the body limit, the timeouts, the rate policies and the CORS policy.
type Limits = (
    BodyLimit,
    RouteTimeouts,
    Vec<RatePolicyId>,
    Option<CorsPolicy>,
);

/// The validated target of the draft; the violations are added to `found` otherwise.
fn target_of(draft: &RouteDraft, found: &mut Vec<InvalidRoute>) -> Option<Target> {
    let host = gather(RouteHost::new(&draft.host), found);
    let methods = gather(methods_of(draft.methods.clone()), found);
    let path_pattern = gather(PathPattern::new(&draft.path_pattern), found);
    let service = gather(service_of(&draft.service), found);
    Some((host?, methods?, path_pattern?, service?))
}

/// The validated limits of the draft; the violations are added to `found` otherwise.
fn limits_of(draft: &RouteDraft, found: &mut Vec<InvalidRoute>) -> Option<Limits> {
    let body_limit = gather(BodyLimit::new(draft.body_limit), found);
    let timeouts = RouteTimeouts::new(draft.request_timeout_ms, draft.idle_timeout_ms);
    let timeouts = gather_all(timeouts, found);
    let rate_policies = gather(rate_policies_of(draft.rate_policies.clone()), found);
    let cors = gather_all(draft.cors.clone().map(CorsPolicy::new).transpose(), found);
    Some((body_limit?, timeouts?, rate_policies?, cors?))
}

/// The value of a result; its violation is added to `found` otherwise.
fn gather<T>(result: Result<T, InvalidRoute>, found: &mut Vec<InvalidRoute>) -> Option<T> {
    result.map_err(|violation| found.push(violation)).ok()
}

/// The value of a result; its violations are added to `found` otherwise.
fn gather_all<T>(result: Result<T, Vec<InvalidRoute>>, found: &mut Vec<InvalidRoute>) -> Option<T> {
    result.map_err(|violations| found.extend(violations)).ok()
}

/// The methods in order, without duplicates; at least one.
fn methods_of(mut methods: Vec<HttpMethod>) -> Result<Vec<HttpMethod>, InvalidRoute> {
    methods.sort();
    methods.dedup();
    if methods.is_empty() {
        return Err(InvalidRoute::MethodsRequired);
    }
    Ok(methods)
}

/// The service name, mapped to the violations of a route.
fn service_of(value: &str) -> Result<ServiceName, InvalidRoute> {
    ServiceName::new(value).map_err(|invalid| {
        if invalid == InvalidIamValue::ServiceNameLength {
            InvalidRoute::ServiceLength
        } else {
            InvalidRoute::ServicePattern
        }
    })
}

/// The rate policies when there are at most ten and none twice.
fn rate_policies_of(ids: Vec<RatePolicyId>) -> Result<Vec<RatePolicyId>, InvalidRoute> {
    if ids.len() > MAX_RATE_POLICIES {
        return Err(InvalidRoute::RatePolicyCount);
    }
    if ids.iter().collect::<BTreeSet<_>>().len() != ids.len() {
        return Err(InvalidRoute::RatePolicyDuplicate);
    }
    Ok(ids)
}
