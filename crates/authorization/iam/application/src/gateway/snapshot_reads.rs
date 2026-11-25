//! The decision data of one request, read from the policy snapshot the request loaded.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use iam_domain::{
    AssignmentState, CatalogueEntryState, CompiledRoleSet, GqlCoordinate, GqlName,
    GraphQlCoordinate, GraphQlField, GraphQlTypeGraph, HttpMethod, InvalidSpec, LogEpoch,
    PathTemplate, PermissionFlags, PermissionKey, PolicyEpoch, PolicyReadRepository,
    PolicySnapshot, PolicyVersion, RelayEpoch, RepositoryError, RestOperation, RestOperationSet,
    RoleAssignment, RoleId, ServiceCatalog, ServiceName, SubjectPolicy, SubjectRef,
};

/// The version of a snapshot a catalogue was derived from: the log epoch and the policy version.
type Stamp = (LogEpoch, PolicyVersion);

/// The catalogue of a service, or none, with the stamp of the snapshot it was derived from.
type Derived = (Stamp, Option<ServiceCatalog>);

/// The catalogues derived from snapshot entries, kept until the snapshot moves on.
///
/// Deriving the operation set of a service parses every key of its catalogue, so the result is
/// kept for as long as the snapshot it came from is the one that is asked about, and a request
/// that loads a newer snapshot derives it again.
#[derive(Debug, Default)]
pub struct CatalogueCache {
    derived: Mutex<HashMap<ServiceName, Derived>>,
}

impl CatalogueCache {
    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn get_or_derive<F>(
        &self,
        service: &ServiceName,
        stamp: Stamp,
        derive: F,
    ) -> Option<ServiceCatalog>
    where
        F: FnOnce() -> Option<ServiceCatalog>,
    {
        let mut derived = self.derived.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((known, catalog)) = derived.get(service)
            && *known == stamp
        {
            return catalog.clone();
        }
        let catalog = derive();
        derived.insert(service.clone(), (stamp, catalog.clone()));
        catalog
    }
}

/// The [`PolicyReadRepository`] of the gateway: it answers from one snapshot, so every read of a
/// request sees the same version (FR-13), and it does no I/O.
///
/// The catalogue of a service holds its REST operations and one GraphQL type graph over the
/// coordinates whose entries carry their return type (Story 10.8); an entry without one is not in
/// the graph, so a document that selects it is refused as an unknown operation.
#[derive(Debug)]
pub struct LoadedSnapshotReads {
    snapshot: Arc<dyn PolicySnapshot>,
    cache: Arc<CatalogueCache>,
}

impl LoadedSnapshotReads {
    /// Reads from `snapshot` and shares the derived catalogues through `cache`.
    #[must_use]
    pub const fn new(snapshot: Arc<dyn PolicySnapshot>, cache: Arc<CatalogueCache>) -> Self {
        Self { snapshot, cache }
    }

    fn epoch(&self) -> Result<PolicyEpoch, RepositoryError> {
        PolicyEpoch::new(
            self.snapshot.version(),
            self.snapshot.digest(),
            self.snapshot.log_epoch(),
            RelayEpoch::ZERO,
            0,
        )
        .ok()
        .ok_or(RepositoryError::NotFound)
    }

    fn subject_policy(&self, subject: &SubjectRef) -> Result<SubjectPolicy, RepositoryError> {
        let held = self.snapshot.assignments(subject);
        let assignments = held.iter().map(assignment).collect();
        let role_sets: BTreeMap<RoleId, CompiledRoleSet> = held
            .iter()
            .filter_map(|state| Some((state.role, self.snapshot.role_set(state.role)?.clone())))
            .collect();
        Ok(SubjectPolicy::new(self.epoch()?, assignments, role_sets))
    }

    fn service_catalog(
        &self,
        service: &ServiceName,
    ) -> Result<Option<ServiceCatalog>, RepositoryError> {
        let epoch = self.epoch()?;
        let stamp = (self.snapshot.log_epoch(), self.snapshot.version());
        Ok(self.cache.get_or_derive(service, stamp, || {
            let entries = self.snapshot.catalogue(service)?;
            Some(ServiceCatalog::new(
                service.clone(),
                epoch,
                vec![rest_operations(service, entries)],
                type_graph(service, entries).into_iter().collect(),
            ))
        }))
    }
}

#[async_trait::async_trait]
impl PolicyReadRepository for LoadedSnapshotReads {
    async fn read_subject_policy(
        &self,
        subject: &SubjectRef,
    ) -> Result<SubjectPolicy, RepositoryError> {
        self.subject_policy(subject)
    }

    async fn read_service_catalog(
        &self,
        service: &ServiceName,
    ) -> Result<Option<ServiceCatalog>, RepositoryError> {
        self.service_catalog(service)
    }
}

/// The assignment of the decision rule: an expiry before 1970 is read as the epoch itself, which
/// is expired, so a record that cannot be read never grants.
fn assignment(state: &AssignmentState) -> RoleAssignment {
    let expires_at = state.expires_at_micros.map(|micros| {
        let elapsed = u64::try_from(micros).unwrap_or_default();
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_micros(elapsed))
            .unwrap_or(SystemTime::UNIX_EPOCH)
    });
    RoleAssignment::new(state.role, state.scope, expires_at)
}

/// The REST operations of the entries of `service`; an entry that is no REST key of the service is
/// not an operation.
fn rest_operations(service: &ServiceName, entries: &[CatalogueEntryState]) -> RestOperationSet {
    let mut operations = RestOperationSet::new();
    for operation in entries.iter().filter_map(|entry| operation(service, entry)) {
        if let Err(error) = operations.insert(operation) {
            log_dropped(&error, service);
        }
    }
    operations
}

/// The type graph of the typed GraphQL entries of `service`; `None` when there is none, or when
/// the entries do not make a valid graph (the service then analyses no document).
fn type_graph(service: &ServiceName, entries: &[CatalogueEntryState]) -> Option<GraphQlTypeGraph> {
    let mut fields = Vec::new();
    let mut possible = Vec::new();
    for entry in entries {
        let Some((coordinate, field)) = typed_field(service, entry) else {
            continue;
        };
        for member in &entry.possible_types {
            if let Some(member) = GqlName::parse(member) {
                possible.push((field.return_type.clone(), member));
            }
        }
        fields.push((coordinate, field));
    }
    if fields.is_empty() {
        return None;
    }
    GraphQlTypeGraph::new(fields, possible)
        .map_err(|error| log_dropped(&error, service))
        .ok()
}

/// The coordinate and the field of a GraphQL entry of `service` that carries its return type.
fn typed_field(
    service: &ServiceName,
    entry: &CatalogueEntryState,
) -> Option<(GraphQlCoordinate, GraphQlField)> {
    let PermissionKey::Gql {
        service: owner,
        coordinate: GqlCoordinate::Field { type_name, field },
    } = PermissionKey::parse(&entry.key).ok()?
    else {
        return None;
    };
    (owner == *service).then_some(())?;
    let return_type = GqlName::parse(entry.return_type.as_deref()?)?;
    Some((
        GraphQlCoordinate::new(type_name, field),
        GraphQlField {
            return_type,
            flags: flags(entry),
        },
    ))
}

fn log_dropped(error: &InvalidSpec, service: &ServiceName) {
    tracing::warn!(error = %error, service = %service, "a catalogue entry was not kept");
}

fn operation(service: &ServiceName, entry: &CatalogueEntryState) -> Option<RestOperation> {
    let (method, template) = rest_key(service, &entry.key)?;
    Some(RestOperation {
        method,
        template,
        label: None,
        flags: flags(entry),
    })
}

/// The method and the template of `key`, when it is a REST key of `service`.
fn rest_key(service: &ServiceName, key: &str) -> Option<(HttpMethod, PathTemplate)> {
    let PermissionKey::Rest {
        service: owner,
        method,
        template,
    } = PermissionKey::parse(key).ok()?
    else {
        return None;
    };
    (owner == *service).then_some(())?;
    Some((method, PathTemplate::from_stored(template.as_str())?))
}

const fn flags(entry: &CatalogueEntryState) -> PermissionFlags {
    let flags = if entry.sensitive {
        PermissionFlags::NONE.with_sensitive()
    } else {
        PermissionFlags::NONE
    };
    if entry.audit_always {
        flags.with_audit_always()
    } else {
        flags
    }
}

#[cfg(test)]
mod tests;
