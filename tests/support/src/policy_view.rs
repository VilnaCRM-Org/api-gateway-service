//! Policy view double of the IAM context.

use std::sync::Arc;
use std::time::Duration;

use iam_domain::{
    AssignmentState, BootInstant, CatalogueEntryState, CompiledRoleSet, FreshnessProof, HttpMethod,
    LogEpoch, PolicyDigestValue, PolicySnapshot, PolicyVersion, PolicyView, RatePolicyId,
    RatePolicyState, RoleId, RouteHost, RouteState, ServiceName, SubjectRef, UpstreamId,
    UpstreamName, UpstreamState,
};

/// A snapshot that holds nothing but a version: no route, no upstream, no role, no assignment and
/// no catalogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptySnapshot {
    version: PolicyVersion,
}

impl EmptySnapshot {
    /// An empty snapshot at `version`.
    #[must_use]
    pub const fn at(version: PolicyVersion) -> Self {
        Self { version }
    }
}

impl PolicySnapshot for EmptySnapshot {
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

    fn role_set(&self, _role: RoleId) -> Option<&CompiledRoleSet> {
        None
    }

    fn assignments(&self, _subject: &SubjectRef) -> &[AssignmentState] {
        &[]
    }

    fn subjects_of_role(&self, _role: RoleId) -> Vec<SubjectRef> {
        Vec::new()
    }

    fn rate_policy(&self, _id: RatePolicyId) -> Option<&RatePolicyState> {
        None
    }

    fn catalogue(&self, _service: &ServiceName) -> Option<&[CatalogueEntryState]> {
        None
    }
}

/// A policy view that answers from memory: the snapshot it was given, or nothing at all.
#[derive(Debug, Clone)]
pub struct FakePolicyView {
    snapshot: Option<Arc<dyn PolicySnapshot>>,
}

impl FakePolicyView {
    /// A view whose snapshot is empty and at version 0.
    #[must_use]
    pub fn new() -> Self {
        Self::with_snapshot(Arc::new(EmptySnapshot::at(PolicyVersion::ZERO)))
    }

    /// A view that has no snapshot yet, as a gateway that did not finish its bootstrap: every
    /// reader finds nothing.
    #[must_use]
    pub const fn failing() -> Self {
        Self { snapshot: None }
    }

    /// A view that hands out `snapshot`.
    #[must_use]
    pub fn with_snapshot(snapshot: Arc<dyn PolicySnapshot>) -> Self {
        Self {
            snapshot: Some(snapshot),
        }
    }
}

impl Default for FakePolicyView {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyView for FakePolicyView {
    fn current(&self) -> Option<Arc<dyn PolicySnapshot>> {
        self.snapshot.clone()
    }
}

#[cfg(test)]
mod tests;
