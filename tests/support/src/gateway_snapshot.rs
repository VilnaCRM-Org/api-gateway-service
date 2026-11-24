//! A policy snapshot double for the gateway pipeline: routes, upstreams, catalogues, role sets,
//! assignments and revocation records, and a policy view that counts its loads.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use iam_domain::{
    AssignmentState, BootInstant, CatalogueEntryState, CompiledRoleSet, FreshnessProof,
    GlobalRevocationState, HttpMethod, LogEpoch, PathSegment, PolicyDigestValue, PolicySnapshot,
    PolicyVersion, PolicyView, RatePolicyId, RatePolicyState, RoleId, RouteHost, RouteState,
    ServiceName, SessionId, SubjectRef, UpstreamId, UpstreamName, UpstreamState,
    UserRevocationState,
};
use shared_domain::Uuid;

/// A snapshot at a version that holds what it was given and nothing else.
///
/// A route matches the host, a method of the route and the path that its pattern describes: a
/// parameter segment matches any one segment and a catch-all matches the rest.
#[derive(Debug, Clone)]
pub struct GatewaySnapshot {
    version: PolicyVersion,
    routes: Vec<RouteState>,
    upstreams: Vec<UpstreamState>,
    assignments: BTreeMap<SubjectRef, Vec<AssignmentState>>,
    role_sets: BTreeMap<RoleId, CompiledRoleSet>,
    catalogues: BTreeMap<ServiceName, Vec<CatalogueEntryState>>,
    revoked_sessions: Vec<SessionId>,
    user_cutoffs: Vec<UserRevocationState>,
    global_cutoff: Option<GlobalRevocationState>,
}

impl GatewaySnapshot {
    /// An empty snapshot at `version`.
    #[must_use]
    pub const fn at(version: PolicyVersion) -> Self {
        Self {
            version,
            routes: Vec::new(),
            upstreams: Vec::new(),
            assignments: BTreeMap::new(),
            role_sets: BTreeMap::new(),
            catalogues: BTreeMap::new(),
            revoked_sessions: Vec::new(),
            user_cutoffs: Vec::new(),
            global_cutoff: None,
        }
    }

    /// The same snapshot that also holds `route`.
    #[must_use]
    pub fn with_route(mut self, route: RouteState) -> Self {
        self.routes.push(route);
        self
    }

    /// The same snapshot that also holds `upstream`.
    #[must_use]
    pub fn with_upstream(mut self, upstream: UpstreamState) -> Self {
        self.upstreams.push(upstream);
        self
    }

    /// The same snapshot that also holds the assignments of `subject`.
    #[must_use]
    pub fn with_assignments(mut self, subject: SubjectRef, held: Vec<AssignmentState>) -> Self {
        self.assignments.insert(subject, held);
        self
    }

    /// The same snapshot that also holds the compiled set of `role`.
    #[must_use]
    pub fn with_role_set(mut self, role: RoleId, set: CompiledRoleSet) -> Self {
        self.role_sets.insert(role, set);
        self
    }

    /// The same snapshot that also holds the catalogue of `service`.
    #[must_use]
    pub fn with_catalogue(
        mut self,
        service: ServiceName,
        entries: Vec<CatalogueEntryState>,
    ) -> Self {
        self.catalogues.insert(service, entries);
        self
    }

    /// The same snapshot with `session` revoked.
    #[must_use]
    pub fn with_revoked_session(mut self, session: SessionId) -> Self {
        self.revoked_sessions.push(session);
        self
    }

    /// The same snapshot with the cut-off of a user.
    #[must_use]
    pub fn with_user_cutoff(mut self, state: UserRevocationState) -> Self {
        self.user_cutoffs.push(state);
        self
    }

    /// The same snapshot with the global cut-off.
    #[must_use]
    pub const fn with_global_cutoff(mut self, state: GlobalRevocationState) -> Self {
        self.global_cutoff = Some(state);
        self
    }
}

/// Whether the segments of `path` fit `pattern`.
fn fits(pattern: &[PathSegment], path: &str) -> bool {
    let segments: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    for (position, expected) in pattern.iter().enumerate() {
        match (expected, segments.get(position)) {
            (PathSegment::CatchAll(_), Some(_)) => return true,
            (PathSegment::Literal(text), Some(segment)) if text == segment => {}
            (PathSegment::Parameter(_), Some(_)) => {}
            _ => return false,
        }
    }
    pattern.len() == segments.len()
}

impl PolicySnapshot for GatewaySnapshot {
    fn version(&self) -> PolicyVersion {
        self.version
    }

    fn digest(&self) -> PolicyDigestValue {
        PolicyDigestValue::ZERO
    }

    fn derived_hash(&self) -> PolicyDigestValue {
        PolicyDigestValue::ZERO
    }

    fn accounted_bytes(&self) -> usize {
        0
    }

    fn log_epoch(&self) -> LogEpoch {
        LogEpoch::ZERO
    }

    fn freshness_proof(&self) -> FreshnessProof {
        FreshnessProof {
            version: self.version,
            published_at: BootInstant::from_elapsed(Duration::ZERO),
        }
    }

    fn route(&self, host: &RouteHost, method: HttpMethod, path: &str) -> Option<&RouteState> {
        self.routes.iter().find(|route| {
            route.fields.host() == host
                && route.fields.methods().contains(&method)
                && fits(route.fields.path_pattern().segments(), path)
        })
    }

    fn upstream(&self, name: &UpstreamName) -> Option<&UpstreamState> {
        self.upstreams
            .iter()
            .find(|upstream| upstream.name == *name)
    }

    fn upstream_by_id(&self, id: UpstreamId) -> Option<&UpstreamState> {
        self.upstreams.iter().find(|upstream| upstream.id == id)
    }

    fn role_set(&self, role: RoleId) -> Option<&CompiledRoleSet> {
        self.role_sets.get(&role)
    }

    fn assignments(&self, subject: &SubjectRef) -> &[AssignmentState] {
        self.assignments.get(subject).map_or(&[], Vec::as_slice)
    }

    fn subjects_of_role(&self, _role: RoleId) -> Vec<SubjectRef> {
        Vec::new()
    }

    fn rate_policy(&self, _id: RatePolicyId) -> Option<&RatePolicyState> {
        None
    }

    fn catalogue(&self, service: &ServiceName) -> Option<&[CatalogueEntryState]> {
        self.catalogues.get(service).map(Vec::as_slice)
    }

    fn session_revoked(&self, session: &SessionId) -> bool {
        self.revoked_sessions.contains(session)
    }

    fn user_cutoff(&self, user: Uuid) -> Option<&UserRevocationState> {
        self.user_cutoffs.iter().find(|state| state.user == user)
    }

    fn global_cutoff(&self) -> Option<&GlobalRevocationState> {
        self.global_cutoff.as_ref()
    }
}

/// A policy view that hands out one snapshot, or none, and counts how often it was asked.
#[derive(Debug, Clone)]
pub struct CountingPolicyView {
    snapshot: Option<Arc<dyn PolicySnapshot>>,
    loads: Arc<AtomicUsize>,
}

impl CountingPolicyView {
    /// A view that hands out `snapshot`.
    #[must_use]
    pub fn serving(snapshot: GatewaySnapshot) -> Self {
        Self {
            snapshot: Some(Arc::new(snapshot)),
            loads: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// A view that has no snapshot yet.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            snapshot: None,
            loads: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// How many handles to the snapshot exist: the view's own and every reader that still holds one.
    #[must_use]
    pub fn snapshot_handles(&self) -> usize {
        self.snapshot.as_ref().map_or(0, Arc::strong_count)
    }

    /// How many times a reader asked for the snapshot.
    #[must_use]
    pub fn loads(&self) -> usize {
        self.loads.load(Ordering::SeqCst)
    }
}

impl PolicyView for CountingPolicyView {
    fn current(&self) -> Option<Arc<dyn PolicySnapshot>> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        self.snapshot.clone()
    }
}

#[cfg(test)]
mod tests;
