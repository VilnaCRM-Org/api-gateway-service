//! Route repository double and route fixtures of the IAM context.

use async_trait::async_trait;
use iam_domain::{
    ChangeStatement, EnforcementMode, EntityVersion, HttpMethod, IamChange, RatePolicyId,
    RepositoryError, RetryPolicy, Route, RouteDraft, RouteFields, RouteFlags, RouteHost, RouteId,
    RoutePageQuery, RouteParts, RouteRepository, RouteStatement, UpstreamId,
};

use crate::gateway_configuration::{gateway_change, random_time};
use crate::seed::TestRng;
use crate::unit_of_work::uuid_v7;

/// A valid draft of a protected, enforced route of the catalogue service `service` on `host` for
/// `path_pattern` and `methods`, that forwards to `upstream`.
#[must_use]
pub fn route_draft(
    host: &str,
    path_pattern: &str,
    methods: &[HttpMethod],
    service: &str,
    upstream: UpstreamId,
) -> RouteDraft {
    RouteDraft {
        host: host.to_owned(),
        methods: methods.to_vec(),
        path_pattern: path_pattern.to_owned(),
        service: service.to_owned(),
        upstream_id: upstream,
        flags: RouteFlags::default(),
        enforcement: EnforcementMode::Enforce,
        body_limit: 1_048_576,
        request_timeout_ms: 30_000,
        idle_timeout_ms: 60_000,
        retry: RetryPolicy::None,
        rate_policies: Vec::new(),
        cors: None,
    }
}

/// A stored route of `draft` at version 1, created and updated at a random time after 2020.
///
/// # Panics
///
/// Panics when `draft` is not valid.
#[expect(
    clippy::expect_used,
    reason = "a fixture with an invalid draft is a defect of the test"
)]
pub fn route(rng: &mut TestRng, draft: &RouteDraft) -> Route {
    let at = random_time(rng);
    Route::restore(RouteParts {
        id: RouteId::from_uuid(uuid_v7(rng)),
        fields: RouteFields::new(draft).expect("a valid route"),
        system: false,
        version: EntityVersion::INITIAL,
        created_at: at,
        updated_at: at,
        deleted_at: None,
    })
}

/// A random committed change that runs `statements`.
pub fn route_change(rng: &mut TestRng, statements: Vec<RouteStatement>) -> IamChange {
    gateway_change(
        rng,
        statements.into_iter().map(ChangeStatement::from).collect(),
    )
}

/// What the double answers with.
#[derive(Debug)]
enum Answer {
    Holding(Vec<RouteParts>),
    Failing,
}

/// A route repository that answers from memory with the rules of the port: deleted routes are never
/// found, and pages follow the order of the identifiers.
#[derive(Debug)]
pub struct FakeRouteRepository {
    answer: Answer,
}

impl FakeRouteRepository {
    /// A repository without routes.
    #[must_use]
    pub const fn new() -> Self {
        Self::holding(Vec::new())
    }

    /// A repository that holds the state of each route.
    #[must_use]
    pub const fn holding(routes: Vec<RouteParts>) -> Self {
        Self {
            answer: Answer::Holding(routes),
        }
    }

    /// A repository that answers `Unavailable`.
    #[must_use]
    pub const fn failing() -> Self {
        Self {
            answer: Answer::Failing,
        }
    }

    /// The routes that are not deleted, in the order of their identifiers.
    fn live(&self) -> Result<Vec<&RouteParts>, RepositoryError> {
        match &self.answer {
            Answer::Holding(routes) => {
                let mut live: Vec<&RouteParts> = routes
                    .iter()
                    .filter(|route| route.deleted_at.is_none())
                    .collect();
                live.sort_by_key(|route| route.id);
                Ok(live)
            }
            Answer::Failing => Err(RepositoryError::Unavailable(
                "in-memory repository failure".into(),
            )),
        }
    }
}

impl Default for FakeRouteRepository {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether `route` matches the filters and comes after the cursor of `query`.
fn selected(route: &RouteParts, query: &RoutePageQuery) -> bool {
    let fields = &route.fields;
    query.after.is_none_or(|after| route.id > after)
        && query.host.as_ref().is_none_or(|host| fields.host() == host)
        && query
            .upstream
            .is_none_or(|upstream| fields.upstream_id() == upstream)
        && query
            .service
            .as_ref()
            .is_none_or(|service| fields.service() == service)
}

#[async_trait]
impl RouteRepository for FakeRouteRepository {
    async fn find_by_id(&self, id: RouteId) -> Result<Option<Route>, RepositoryError> {
        Ok(self
            .live()?
            .into_iter()
            .find(|route| route.id == id)
            .map(|route| Route::restore(route.clone())))
    }

    async fn find_page(&self, query: &RoutePageQuery) -> Result<Vec<Route>, RepositoryError> {
        let limit = usize::try_from(query.limit).unwrap_or(usize::MAX);
        Ok(self
            .live()?
            .into_iter()
            .filter(|route| selected(route, query))
            .take(limit)
            .map(|route| Route::restore(route.clone()))
            .collect())
    }

    async fn find_by_host(&self, host: &RouteHost) -> Result<Vec<Route>, RepositoryError> {
        Ok(self
            .live()?
            .into_iter()
            .filter(|route| route.fields.host() == host)
            .map(|route| Route::restore(route.clone()))
            .collect())
    }

    async fn count_by_upstream(&self, upstream: UpstreamId) -> Result<u64, RepositoryError> {
        let count = self
            .live()?
            .into_iter()
            .filter(|route| route.fields.upstream_id() == upstream)
            .count();
        Ok(u64::try_from(count).unwrap_or(u64::MAX))
    }

    async fn count_by_rate_policy(&self, policy: RatePolicyId) -> Result<u64, RepositoryError> {
        let count = self
            .live()?
            .into_iter()
            .filter(|route| route.fields.rate_policies().contains(&policy))
            .count();
        Ok(u64::try_from(count).unwrap_or(u64::MAX))
    }
}

#[cfg(test)]
mod tests;
