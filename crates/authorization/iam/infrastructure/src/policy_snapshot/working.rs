//! The state the builder works on and the snapshot reads: the shards of the raw state and the
//! structures derived from them.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use iam_domain::{
    AssignmentState, CatalogueEntryState, CompiledRoleSet, HttpMethod, LogEpoch, PolicyDigestValue,
    PolicyState, PolicyVersion, RatePolicyId, RatePolicyState, RoleId, RouteHost, RouteId,
    RouteMatcher, RouteState, ServiceName, StateKey, SubjectRef, UpstreamId, UpstreamName,
    UpstreamState,
};

use super::shards::{Derived, Entry, Shards};

/// What one compiled grant is counted as: its key or pattern and the node of its set.
const GRANT_BYTES: usize = 96;

mod apply;

pub(super) use apply::Applier;

/// The routes of one host: their identifiers and the matcher compiled from them.
#[derive(Debug, Clone)]
pub(super) struct HostRoutes {
    pub(super) ids: BTreeSet<RouteId>,
    pub(super) matcher: Arc<dyn RouteMatcher>,
}

/// The raw state and everything derived from it, at one policy version.
#[derive(Debug, Clone)]
pub(super) struct Working {
    pub(super) shards: Shards,
    pub(super) version: PolicyVersion,
    pub(super) digest: PolicyDigestValue,
    pub(super) derived_hash: PolicyDigestValue,
    pub(super) log_epoch: LogEpoch,
    pub(super) hosts: Arc<BTreeMap<RouteHost, HostRoutes>>,
    pub(super) upstream_ids: Arc<BTreeMap<UpstreamId, UpstreamName>>,
    pub(super) role_subjects: Arc<BTreeMap<RoleId, Arc<BTreeSet<SubjectRef>>>>,
    pub(super) catalogues: Arc<BTreeMap<ServiceName, Arc<[CatalogueEntryState]>>>,
}

impl Working {
    /// The state before the first version: nothing is known.
    pub(super) fn empty(log_epoch: LogEpoch) -> Self {
        Self {
            shards: Shards::new(),
            version: PolicyVersion::ZERO,
            digest: PolicyDigestValue::ZERO,
            derived_hash: PolicyDigestValue::ZERO,
            log_epoch,
            hosts: Arc::default(),
            upstream_ids: Arc::default(),
            role_subjects: Arc::default(),
            catalogues: Arc::default(),
        }
    }

    pub(super) fn route(
        &self,
        host: &RouteHost,
        method: HttpMethod,
        path: &str,
    ) -> Option<&RouteState> {
        let id = self.hosts.get(host)?.matcher.find(method, path)?;
        let PolicyState::Route(route) = &self.shards.get(&StateKey::Route(id))?.state else {
            return None;
        };
        Some(route)
    }

    pub(super) fn upstream(&self, name: &UpstreamName) -> Option<&UpstreamState> {
        let PolicyState::Upstream(upstream) =
            &self.shards.get(&StateKey::Upstream(name.clone()))?.state
        else {
            return None;
        };
        Some(upstream)
    }

    pub(super) fn upstream_by_id(&self, id: UpstreamId) -> Option<&UpstreamState> {
        self.upstream(self.upstream_ids.get(&id)?)
    }

    pub(super) fn role_set(&self, role: RoleId) -> Option<&CompiledRoleSet> {
        let Derived::Role(compiled) = &self.shards.get(&StateKey::Role(role))?.derived else {
            return None;
        };
        Some(compiled)
    }

    pub(super) fn assignments(&self, subject: &SubjectRef) -> &[AssignmentState] {
        let Some(entry) = self.shards.get(&StateKey::Subject(subject.clone())) else {
            return &[];
        };
        let Derived::Subject(list) = &entry.derived else {
            return &[];
        };
        list
    }

    pub(super) fn subjects_of_role(&self, role: RoleId) -> Vec<SubjectRef> {
        self.role_subjects
            .get(&role)
            .map(|subjects| subjects.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub(super) fn rate_policy(&self, id: RatePolicyId) -> Option<&RatePolicyState> {
        let PolicyState::RatePolicy(policy) = &self.shards.get(&StateKey::RatePolicy(id))?.state
        else {
            return None;
        };
        Some(policy)
    }

    /// An estimate of the bytes that the raw state and the derived structures hold. A list shared
    /// by several subjects is counted once.
    pub(super) fn accounted_bytes(&self) -> usize {
        let mut lists = BTreeSet::new();
        let entries = self.shards.iter().fold(0_usize, |total, (key, entry)| {
            let own = size_of::<StateKey>()
                .saturating_add(size_of::<Entry>())
                .saturating_add(key.to_string().len());
            let derived = match &entry.derived {
                Derived::Role(compiled) => size_of::<CompiledRoleSet>().saturating_add(
                    compiled
                        .key_count()
                        .saturating_add(compiled.wildcard_count())
                        .saturating_mul(GRANT_BYTES),
                ),
                Derived::Subject(list) if lists.insert(Arc::as_ptr(list).addr()) => {
                    list.len().saturating_mul(size_of::<AssignmentState>())
                }
                Derived::Nothing | Derived::Subject(_) => 0,
            };
            total.saturating_add(own).saturating_add(derived)
        });
        let index = self
            .role_subjects
            .values()
            .map(|subjects| subjects.len().saturating_mul(size_of::<SubjectRef>()))
            .fold(0_usize, usize::saturating_add);
        entries.saturating_add(index)
    }

    pub(super) fn catalogue(&self, service: &ServiceName) -> Option<&[CatalogueEntryState]> {
        self.catalogues.get(service).map(AsRef::as_ref)
    }
}

#[cfg(test)]
mod tests;
