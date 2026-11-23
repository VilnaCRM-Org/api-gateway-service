//! The published snapshot: the working state at one version, frozen.

use iam_domain::{
    AssignmentState, BootInstant, CatalogueEntryState, CompiledRoleSet, FreshnessProof, HttpMethod,
    LogEpoch, PolicyDigestValue, PolicySnapshot, PolicyVersion, RatePolicyId, RatePolicyState,
    RoleId, RouteHost, RouteState, ServiceName, SubjectRef, UpstreamId, UpstreamName,
    UpstreamState,
};

use super::working::Working;

/// One policy version, held by readers through an `Arc`.
#[derive(Debug)]
pub(super) struct SnapshotData {
    working: Working,
    published_at: BootInstant,
}

impl SnapshotData {
    pub(super) const fn new(working: Working, published_at: BootInstant) -> Self {
        Self {
            working,
            published_at,
        }
    }

    /// The live keys of the raw state with their versions and states, in key order.
    #[cfg(test)]
    pub(super) fn raw_entries(
        &self,
    ) -> Vec<(iam_domain::StateKey, PolicyVersion, iam_domain::PolicyState)> {
        let mut entries: Vec<_> = self
            .working
            .shards
            .iter()
            .map(|(key, entry)| (key.clone(), entry.version, entry.state.clone()))
            .collect();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        entries
    }

    #[cfg(test)]
    pub(super) const fn working(&self) -> &Working {
        &self.working
    }
}

impl PolicySnapshot for SnapshotData {
    fn version(&self) -> PolicyVersion {
        self.working.version
    }

    fn digest(&self) -> PolicyDigestValue {
        self.working.digest
    }

    fn derived_hash(&self) -> PolicyDigestValue {
        self.working.derived_hash
    }

    fn accounted_bytes(&self) -> usize {
        self.working.accounted_bytes()
    }

    fn log_epoch(&self) -> LogEpoch {
        self.working.log_epoch
    }

    fn freshness_proof(&self) -> FreshnessProof {
        FreshnessProof {
            version: self.working.version,
            published_at: self.published_at,
        }
    }

    fn route(&self, host: &RouteHost, method: HttpMethod, path: &str) -> Option<&RouteState> {
        self.working.route(host, method, path)
    }

    fn upstream(&self, name: &UpstreamName) -> Option<&UpstreamState> {
        self.working.upstream(name)
    }

    fn upstream_by_id(&self, id: UpstreamId) -> Option<&UpstreamState> {
        self.working.upstream_by_id(id)
    }

    fn role_set(&self, role: RoleId) -> Option<&CompiledRoleSet> {
        self.working.role_set(role)
    }

    fn assignments(&self, subject: &SubjectRef) -> &[AssignmentState] {
        self.working.assignments(subject)
    }

    fn subjects_of_role(&self, role: RoleId) -> Vec<SubjectRef> {
        self.working.subjects_of_role(role)
    }

    fn rate_policy(&self, id: RatePolicyId) -> Option<&RatePolicyState> {
        self.working.rate_policy(id)
    }

    fn catalogue(&self, service: &ServiceName) -> Option<&[CatalogueEntryState]> {
        self.working.catalogue(service)
    }
}
