//! The gateway configuration that the bootstrap seeds for IAM's own management API (FR-5): the
//! upstream `iam-control` and the routes of IAM's host that forward to it.

use crate::route::fields::RouteDraft;
use crate::route::settings::{EnforcementMode, RetryPolicy, RouteFlag, RouteFlags};
use crate::upstream::settings::{UpstreamProtocol, UpstreamSettingsDraft};
use crate::value_object::http_method::HttpMethod;
use crate::value_object::identifier::UpstreamId;
use crate::value_object::route_host::RouteHost;

/// The largest request body of the management routes other than the specification uploads: 1 MiB.
const REST_BODY_LIMIT_BYTES: i64 = 1_048_576;

/// The largest request body of the GraphQL route and of the specification upload routes: 6 MiB,
/// which leaves room above the 5 MiB document limit for the JSON envelope and its escapes.
const LARGE_BODY_LIMIT_BYTES: i64 = 6_291_456;

/// The request timeout of every seeded route, in milliseconds.
const REQUEST_TIMEOUT_MS: i64 = 30_000;

/// The idle timeout of every seeded route, in milliseconds.
const IDLE_TIMEOUT_MS: i64 = 60_000;

/// The methods of the REST management routes.
const REST_METHODS: [HttpMethod; 6] = [
    HttpMethod::Get,
    HttpMethod::Head,
    HttpMethod::Post,
    HttpMethod::Put,
    HttpMethod::Patch,
    HttpMethod::Delete,
];

/// One seeded route, before it is bound to a host and an upstream.
#[derive(Debug, Clone, Copy)]
struct SeededRoute {
    methods: &'static [HttpMethod],
    path_pattern: &'static str,
    graphql: bool,
    body_limit: i64,
}

/// The routes of IAM's management API: the REST paths under `/api` as a catch-all, and, more
/// specific, the GraphQL route and the two routes that upload a specification document.
const ROUTES: [SeededRoute; 4] = [
    SeededRoute {
        methods: &REST_METHODS,
        path_pattern: "/api/{rest:*}",
        graphql: false,
        body_limit: REST_BODY_LIMIT_BYTES,
    },
    SeededRoute {
        methods: &[HttpMethod::Post],
        path_pattern: "/api/graphql",
        graphql: true,
        body_limit: LARGE_BODY_LIMIT_BYTES,
    },
    SeededRoute {
        methods: &[HttpMethod::Post],
        path_pattern: "/api/openapi-specs",
        graphql: false,
        body_limit: LARGE_BODY_LIMIT_BYTES,
    },
    SeededRoute {
        methods: &[HttpMethod::Post],
        path_pattern: "/api/graphql-specs",
        graphql: false,
        body_limit: LARGE_BODY_LIMIT_BYTES,
    },
];

/// The upstream and the routes that expose IAM's management API on `host`.
///
/// Every seeded entry belongs to the catalogue service `iam`, enforces its decisions and is a
/// system entry, which the API cannot change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IamGatewaySeed {
    host: RouteHost,
}

impl IamGatewaySeed {
    /// The name of the seeded upstream.
    pub const UPSTREAM_NAME: &'static str = "iam-control";

    /// The Kubernetes namespace IAM itself runs in: the seeded upstream lives there, and the API
    /// never lets an upstream target it, whatever the configuration says.
    pub const NAMESPACE: &'static str = "iam";

    /// Whether `name` is the upstream name that the API reserves for the seeded system upstream:
    /// a create or an update that names it is refused as a system entry.
    #[must_use]
    pub fn reserves_upstream_name(name: &str) -> bool {
        name == Self::UPSTREAM_NAME
    }

    /// The seed for the routes of `host`.
    #[must_use]
    pub const fn new(host: RouteHost) -> Self {
        Self { host }
    }

    /// The host of the seeded routes.
    #[must_use]
    pub const fn host(&self) -> &RouteHost {
        &self.host
    }

    /// The settings of the upstream `iam-control`: the Kubernetes Service `iam-control` of the
    /// namespace `iam` on port 80 over HTTP/1.1, which receives the caller's credentials.
    #[must_use]
    pub fn upstream_draft() -> UpstreamSettingsDraft {
        UpstreamSettingsDraft {
            namespace: Self::NAMESPACE.to_owned(),
            service_name: Self::UPSTREAM_NAME.to_owned(),
            catalog_service: "iam".to_owned(),
            port: 80,
            protocol: UpstreamProtocol::Http1,
            forward_credentials: true,
            connect_timeout_ms: 1_000,
            response_timeout_ms: 30_000,
            concurrency_limit: 1_024,
            retry_budget_percent: 0,
            outlier_threshold: 5,
        }
    }

    /// The drafts of the seeded routes, in the order they are inserted, that forward to
    /// `upstream_id`.
    #[must_use]
    pub fn route_drafts(&self, upstream_id: UpstreamId) -> Vec<RouteDraft> {
        ROUTES
            .iter()
            .map(|route| self.draft_of(route, upstream_id))
            .collect()
    }

    fn draft_of(&self, route: &SeededRoute, upstream_id: UpstreamId) -> RouteDraft {
        RouteDraft {
            host: self.host.as_str().to_owned(),
            methods: route.methods.to_vec(),
            path_pattern: route.path_pattern.to_owned(),
            service: "iam".to_owned(),
            upstream_id,
            flags: RouteFlags::default().with(RouteFlag::Graphql, route.graphql),
            enforcement: EnforcementMode::Enforce,
            body_limit: route.body_limit,
            request_timeout_ms: REQUEST_TIMEOUT_MS,
            idle_timeout_ms: IDLE_TIMEOUT_MS,
            retry: RetryPolicy::None,
            rate_policies: Vec::new(),
            cors: None,
        }
    }
}

#[cfg(test)]
mod tests;
