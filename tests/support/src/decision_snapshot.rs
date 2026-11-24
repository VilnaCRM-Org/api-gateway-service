//! A policy snapshot double that holds what the decision path reads: the assignments of subjects,
//! the compiled sets of roles and the catalogues of services.

use std::collections::BTreeMap;
use std::time::Duration;

use iam_domain::{
    AssignmentState, BootInstant, CatalogueEntryState, CompiledRoleSet, FreshnessProof,
    GlobalRevocationState, HttpMethod, LogEpoch, PolicyDigestValue, PolicySnapshot, PolicyVersion,
    RatePolicyId, RatePolicyState, RoleId, RouteHost, RouteState, ServiceName, SessionId,
    SubjectRef, UpstreamId, UpstreamName, UpstreamState, UserRevocationState,
};
use shared_domain::Uuid;

/// A snapshot at a version that holds the assignments, role sets and catalogues it was given and
/// nothing else.
#[derive(Debug, Clone)]
pub struct DecisionSnapshot {
    version: PolicyVersion,
    assignments: BTreeMap<SubjectRef, Vec<AssignmentState>>,
    role_sets: BTreeMap<RoleId, CompiledRoleSet>,
    catalogues: BTreeMap<ServiceName, Vec<CatalogueEntryState>>,
}

impl DecisionSnapshot {
    /// An empty snapshot at `version`.
    #[must_use]
    pub const fn at(version: PolicyVersion) -> Self {
        Self {
            version,
            assignments: BTreeMap::new(),
            role_sets: BTreeMap::new(),
            catalogues: BTreeMap::new(),
        }
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
}

impl PolicySnapshot for DecisionSnapshot {
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

    fn route(&self, _host: &RouteHost, _method: HttpMethod, _path: &str) -> Option<&RouteState> {
        None
    }

    fn upstream(&self, _name: &UpstreamName) -> Option<&UpstreamState> {
        None
    }

    fn upstream_by_id(&self, _id: UpstreamId) -> Option<&UpstreamState> {
        None
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

    fn session_revoked(&self, _session: &SessionId) -> bool {
        false
    }

    fn user_cutoff(&self, _user: Uuid) -> Option<&UserRevocationState> {
        None
    }

    fn global_cutoff(&self) -> Option<&GlobalRevocationState> {
        None
    }
}
