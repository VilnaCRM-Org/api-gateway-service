//! Applies the changes of one complete version to the working state, all or nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ApplyRules, CatalogueEntryState, HttpMethod, LogEpoch, PolicyDigest, PolicyDigestValue,
    PolicyHead, PolicyState, PolicyVersion, RoleId, RouteHost, RouteId, RouteMatcher, RouteParts,
    RouteState, RouteTableCompiler, ServiceName, StateKey, StateRecordCodec, SubjectRef,
};

use super::{HostRoutes, Working};
use crate::policy_snapshot::builder::SnapshotBuildError;
use crate::policy_snapshot::derived::{Interner, derive, items, roles_of};
use crate::policy_snapshot::shards::{Derived, Entry};

/// One record of a version, decoded and hashed.
#[derive(Debug)]
pub(in crate::policy_snapshot) struct Change {
    pub(in crate::policy_snapshot) key: StateKey,
    pub(in crate::policy_snapshot) version: PolicyVersion,
    pub(in crate::policy_snapshot) state: Option<PolicyState>,
    pub(in crate::policy_snapshot) hash: PolicyDigestValue,
    pub(in crate::policy_snapshot) derived: Derived,
}

/// The ports the application of a version needs, and the interner of assignment lists.
#[derive(Debug)]
pub(in crate::policy_snapshot) struct Applier {
    codec: Arc<dyn StateRecordCodec>,
    digest: Arc<dyn PolicyDigest>,
    compiler: Arc<dyn RouteTableCompiler>,
    interner: Interner,
}

type StagedHosts = Vec<(RouteHost, Option<HostRoutes>)>;

impl Applier {
    pub(in crate::policy_snapshot) fn new(
        codec: Arc<dyn StateRecordCodec>,
        digest: Arc<dyn PolicyDigest>,
        compiler: Arc<dyn RouteTableCompiler>,
    ) -> Self {
        Self {
            codec,
            digest,
            compiler,
            interner: Interner::default(),
        }
    }

    pub(in crate::policy_snapshot) fn interned_lists(&self) -> usize {
        self.interner.len()
    }

    /// Decodes the payload of one record into a change.
    pub(in crate::policy_snapshot) fn decode(
        &mut self,
        key: &StateKey,
        version: PolicyVersion,
        payload: Option<&str>,
    ) -> Result<Change, SnapshotBuildError> {
        let Some(payload) = payload else {
            return Ok(Change {
                key: key.clone(),
                version,
                state: None,
                hash: PolicyDigestValue::ZERO,
                derived: Derived::Nothing,
            });
        };
        let state = self.codec.decode(key, payload)?;
        if !state.belongs_to(key) {
            return Err(iam_domain::InvalidStateRecord::Field { field: "state" }.into());
        }
        Ok(Change {
            key: key.clone(),
            version,
            derived: derive(&state, &mut self.interner)?,
            state: Some(state),
            hash: self.digest.entity_hash(key, payload),
        })
    }

    /// Decodes the head record of a version.
    pub(in crate::policy_snapshot) fn head(
        &self,
        payload: &str,
    ) -> Result<PolicyHead, SnapshotBuildError> {
        let PolicyState::Head(head) = self.codec.decode(&StateKey::Head, payload)? else {
            return Err(SnapshotBuildError::MissingHead);
        };
        Ok(head)
    }

    /// Applies `changes` to `working` and moves it to `target`. When `expected` is set, the digest
    /// that the changes lead to must equal it, or nothing is applied.
    pub(in crate::policy_snapshot) fn apply(
        &self,
        working: &mut Working,
        changes: Vec<Change>,
        expected: Option<PolicyDigestValue>,
        target: (PolicyVersion, LogEpoch),
    ) -> Result<(), SnapshotBuildError> {
        let changes: Vec<Change> = changes
            .into_iter()
            .filter(|change| {
                let current = working.shards.get(&change.key).map(|entry| entry.version);
                ApplyRules::admits(current, change.version)
            })
            .collect();
        let digest = changes.iter().fold(working.digest, |running, change| {
            let old = working
                .shards
                .get(&change.key)
                .map_or(PolicyDigestValue::ZERO, |entry| entry.hash);
            running.combined(old).combined(change.hash)
        });
        if let Some(expected) = expected
            && expected != digest
        {
            return Err(SnapshotBuildError::DigestMismatch {
                version: target.0,
                expected,
                computed: digest,
            });
        }
        let hosts = self.stage_hosts(working, &changes);
        self.commit(working, changes, hosts);
        working.digest = digest;
        working.version = target.0;
        working.log_epoch = working.log_epoch.max(target.1);
        Ok(())
    }

    /// The routers of the hosts that the changes touch, compiled before anything is written.
    ///
    /// A host whose routes cannot be compiled is isolated: its routes fail closed, so the host
    /// denies every request until a later version gives it a table that compiles, and neither the
    /// other hosts nor the later versions are held back.
    fn stage_hosts(&self, working: &Working, changes: &[Change]) -> StagedHosts {
        let route_changes: BTreeMap<RouteId, &Change> = changes
            .iter()
            .filter_map(|change| {
                let StateKey::Route(id) = &change.key else {
                    return None;
                };
                Some((*id, change))
            })
            .collect();
        let hosts = touched_hosts(working, &route_changes);
        hosts
            .into_iter()
            .map(|(host, ids)| {
                if ids.is_empty() {
                    return (host, None);
                }
                let parts: Vec<RouteParts> = ids
                    .iter()
                    .filter_map(|id| route_after(working, &route_changes, *id))
                    .map(parts_of)
                    .collect();
                let matcher = self
                    .compiler
                    .compile(&host, &parts)
                    .unwrap_or_else(|conflict| {
                        tracing::error!(
                            host = %host,
                            %conflict,
                            "the routes of a host do not compile; the host is isolated and denies"
                        );
                        Box::new(IsolatedHost)
                    });
                (
                    host,
                    Some(HostRoutes {
                        ids,
                        matcher: Arc::from(matcher),
                    }),
                )
            })
            .collect()
    }

    fn commit(&self, working: &mut Working, changes: Vec<Change>, hosts: StagedHosts) {
        let mut derived_hash = working.derived_hash;
        let mut services = BTreeSet::new();
        for change in changes {
            let old = working.shards.remove(&change.key);
            self.move_items(&mut derived_hash, &change, old.as_ref());
            update_indexes(working, &change, old.as_ref());
            if let Some(service) = catalogue_service(&change.key) {
                services.insert(service.clone());
            }
            if let Some(state) = change.state {
                working.shards.insert(
                    change.key,
                    Entry {
                        version: change.version,
                        state,
                        hash: change.hash,
                        derived: change.derived,
                    },
                );
            }
        }
        apply_hosts(working, hosts);
        for service in services {
            self.refresh_catalogue(working, &mut derived_hash, service);
        }
        working.derived_hash = derived_hash;
    }

    pub(in crate::policy_snapshot) fn item_hash(&self, text: &str) -> PolicyDigestValue {
        self.digest.entity_hash(&StateKey::Head, text)
    }

    fn move_items(&self, hash: &mut PolicyDigestValue, change: &Change, old: Option<&Entry>) {
        let old_items = old
            .map(|entry| items(&change.key, &entry.state, &entry.derived))
            .unwrap_or_default();
        let new_items = change
            .state
            .as_ref()
            .map(|state| items(&change.key, state, &change.derived))
            .unwrap_or_default();
        for item in old_items.iter().chain(&new_items) {
            *hash = hash.combined(self.item_hash(item));
        }
    }

    fn refresh_catalogue(
        &self,
        working: &mut Working,
        hash: &mut PolicyDigestValue,
        service: ServiceName,
    ) {
        let old = working.catalogues.get(&service).cloned();
        let new = catalogue_of(working, &service);
        let text =
            |entries: &Arc<[CatalogueEntryState]>| format!("catalogue|{service}|{entries:?}");
        for entries in old.iter().chain(new.iter()) {
            *hash = hash.combined(self.item_hash(&text(entries)));
        }
        let catalogues = Arc::make_mut(&mut working.catalogues);
        match new {
            Some(entries) => {
                catalogues.insert(service, entries);
            }
            None => {
                catalogues.remove(&service);
            }
        }
    }
}

const fn route_in(change: &Change) -> Option<&RouteState> {
    if let Some(PolicyState::Route(route)) = &change.state {
        Some(route)
    } else {
        None
    }
}

fn stored_route(working: &Working, id: RouteId) -> Option<&RouteState> {
    let PolicyState::Route(route) = &working.shards.get(&StateKey::Route(id))?.state else {
        return None;
    };
    Some(route)
}

/// The route as it is after the changes: the changed state, or the stored one when untouched.
fn route_after<'a>(
    working: &'a Working,
    changes: &BTreeMap<RouteId, &'a Change>,
    id: RouteId,
) -> Option<&'a RouteState> {
    changes
        .get(&id)
        .map_or_else(|| stored_route(working, id), |change| route_in(change))
}

/// The identifiers of the routes of every host that a change touches, after the changes.
fn touched_hosts(
    working: &Working,
    changes: &BTreeMap<RouteId, &Change>,
) -> BTreeMap<RouteHost, BTreeSet<RouteId>> {
    let mut hosts: BTreeMap<RouteHost, BTreeSet<RouteId>> = BTreeMap::new();
    for (id, change) in changes {
        let before = stored_route(working, *id).map(|route| route.fields.host().clone());
        let after = route_in(change).map(|route| route.fields.host().clone());
        for host in before.into_iter().chain(after) {
            hosts.entry(host.clone()).or_insert_with(|| {
                working
                    .hosts
                    .get(&host)
                    .map(|routes| routes.ids.clone())
                    .unwrap_or_default()
            });
        }
    }
    for (id, change) in changes {
        for ids in hosts.values_mut() {
            ids.remove(id);
        }
        if let Some(route) = route_in(change) {
            hosts
                .entry(route.fields.host().clone())
                .or_default()
                .insert(*id);
        }
    }
    hosts
}

/// The route as the matcher compiler takes it. The timestamps are placeholders: a compiler reads
/// the identifier, the host, the methods and the pattern only, and the builder reads no clock.
fn parts_of(route: &RouteState) -> RouteParts {
    RouteParts {
        id: route.id,
        fields: route.fields.clone(),
        system: route.system,
        version: route.version,
        created_at: SystemTime::UNIX_EPOCH,
        updated_at: SystemTime::UNIX_EPOCH,
        deleted_at: None,
    }
}

/// The matcher of a host whose routes do not compile: it finds no route, so every request of the
/// host is denied.
#[derive(Debug)]
struct IsolatedHost;

impl RouteMatcher for IsolatedHost {
    fn find(&self, _method: HttpMethod, _path: &str) -> Option<RouteId> {
        None
    }
}

fn apply_hosts(working: &mut Working, hosts: StagedHosts) {
    if hosts.is_empty() {
        return;
    }
    let map = Arc::make_mut(&mut working.hosts);
    for (host, routes) in hosts {
        match routes {
            Some(routes) => {
                map.insert(host, routes);
            }
            None => {
                map.remove(&host);
            }
        }
    }
}

const fn catalogue_service(key: &StateKey) -> Option<&ServiceName> {
    match key {
        StateKey::CatalogueManifest(service) | StateKey::CatalogueChunk { service, .. } => {
            Some(service)
        }
        StateKey::Role(_)
        | StateKey::Subject(_)
        | StateKey::Route(_)
        | StateKey::Upstream(_)
        | StateKey::RatePolicy(_)
        | StateKey::SessionRevocation(_)
        | StateKey::UserRevocation(_)
        | StateKey::GlobalRevocation
        | StateKey::Head => None,
    }
}

/// The entries of a catalogue, when its manifest and every chunk of it are present.
fn catalogue_of(working: &Working, service: &ServiceName) -> Option<Arc<[CatalogueEntryState]>> {
    let PolicyState::Manifest(manifest) = &working
        .shards
        .get(&StateKey::CatalogueManifest(service.clone()))?
        .state
    else {
        return None;
    };
    let mut entries = Vec::new();
    for chunk in &manifest.chunks {
        let key = StateKey::chunk(service.clone(), chunk.clone());
        let PolicyState::Chunk(stored) = &working.shards.get(&key)?.state else {
            return None;
        };
        entries.extend(stored.entries.iter().cloned());
    }
    Some(Arc::from(entries))
}

fn update_indexes(working: &mut Working, change: &Change, old: Option<&Entry>) {
    if let StateKey::Subject(subject) = &change.key {
        let old_roles = old.map(|entry| roles_in(&entry.state)).unwrap_or_default();
        let new_roles = change.state.as_ref().map(roles_in).unwrap_or_default();
        move_subject(working, subject, &old_roles, &new_roles);
    }
    if matches!(change.key, StateKey::Upstream(_)) {
        let ids = Arc::make_mut(&mut working.upstream_ids);
        if let Some(PolicyState::Upstream(previous)) = old.map(|entry| &entry.state) {
            ids.remove(&previous.id);
        }
        if let Some(PolicyState::Upstream(upstream)) = &change.state {
            ids.insert(upstream.id, upstream.name.clone());
        }
    }
}

fn roles_in(state: &PolicyState) -> BTreeSet<RoleId> {
    if let PolicyState::Subject(subject) = state {
        roles_of(&subject.assignments)
    } else {
        BTreeSet::new()
    }
}

fn move_subject(
    working: &mut Working,
    subject: &SubjectRef,
    old: &BTreeSet<RoleId>,
    new: &BTreeSet<RoleId>,
) {
    if old == new {
        return;
    }
    let index = Arc::make_mut(&mut working.role_subjects);
    for role in old.difference(new) {
        let emptied = index.get_mut(role).is_some_and(|subjects| {
            let subjects = Arc::make_mut(subjects);
            subjects.remove(subject);
            subjects.is_empty()
        });
        if emptied {
            index.remove(role);
        }
    }
    for role in new.difference(old) {
        Arc::make_mut(index.entry(*role).or_default()).insert(subject.clone());
    }
}

#[cfg(test)]
mod tests;
