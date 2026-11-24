//! The policy reads of the gateway's decision API: the decision path of FR-6 over the replicated
//! snapshot instead of PostgreSQL (FR-19, NFR-16).
//!
//! [`SnapshotPolicyReads`] answers [`PolicyReadRepository`] from the snapshot that the
//! [`PolicyView`] publishes. A read serves only a published snapshot whose proof of freshness is
//! within the hard bound, so a stale pod fails every read with `Unavailable`, which the decision
//! path turns into the deny `unavailable` (FR-13); it never answers from an old snapshot.
//!
//! The catalogue of a service is rebuilt from the permission keys of the snapshot: every
//! `rest:{service}:{METHOD} {template}` key is an operation, and every `gql:{service}:{Type}.{field}`
//! key is a coordinate of one type graph. The snapshot carries no return types, so that graph can
//! decide which permission keys exist but cannot analyse a GraphQL document; the gateway's
//! decision handlers decide a document target as `unavailable` for that reason.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    AssignmentState, CatalogueEntryState, GqlCoordinate, GqlName, GraphQlCoordinate, GraphQlField,
    GraphQlTypeGraph, PathTemplate, PermissionFlags, PermissionKey, PolicyEpoch,
    PolicyReadRepository, PolicySnapshot, PolicyView, RelayEpoch, RepositoryError, RestOperation,
    RestOperationSet, RoleAssignment, ServiceCatalog, ServiceName, SubjectPolicy, SubjectRef,
};
use shared_domain::BoxError;

use crate::freshness::FreshnessState;

/// The return type that every field of the rebuilt type graph names: a scalar, because the
/// snapshot does not carry the real one.
const PLACEHOLDER_RETURN_TYPE: &str = "String";

/// Why the snapshot cannot answer a read.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SnapshotUnavailable {
    /// No snapshot is published yet.
    #[error("no policy snapshot is published yet")]
    NotPublished,
    /// The proof of freshness is missing or older than the hard bound.
    #[error("the policy snapshot is not proven fresh")]
    NotFresh,
    /// The snapshot holds a value the decision path cannot use.
    #[error("the policy snapshot holds {0} that cannot be used")]
    Unusable(&'static str),
}

impl From<SnapshotUnavailable> for RepositoryError {
    fn from(reason: SnapshotUnavailable) -> Self {
        Self::Unavailable(BoxError::from(reason))
    }
}

/// Answers the policy reads of the decision path from the published snapshot.
#[derive(Debug)]
pub struct SnapshotPolicyReads {
    view: Arc<dyn PolicyView>,
    freshness: Arc<FreshnessState>,
}

impl SnapshotPolicyReads {
    /// Reads from the snapshot of `view` while `freshness` finds the pod fresh.
    #[must_use]
    pub const fn new(view: Arc<dyn PolicyView>, freshness: Arc<FreshnessState>) -> Self {
        Self { view, freshness }
    }

    /// The snapshot that serves a decision now: published, and with a proof within the hard bound.
    ///
    /// # Errors
    ///
    /// [`SnapshotUnavailable::NotPublished`] before the first snapshot and
    /// [`SnapshotUnavailable::NotFresh`] when the proof is missing or too old.
    pub fn serving(&self) -> Result<Arc<dyn PolicySnapshot>, SnapshotUnavailable> {
        let snapshot = self
            .view
            .current()
            .ok_or(SnapshotUnavailable::NotPublished)?;
        if self.freshness.is_fresh() {
            Ok(snapshot)
        } else {
            Err(SnapshotUnavailable::NotFresh)
        }
    }

    fn subject_policy(&self, subject: &SubjectRef) -> Result<SubjectPolicy, RepositoryError> {
        let snapshot = self.serving()?;
        Ok(policy_of(snapshot.as_ref(), subject)?)
    }

    fn service_catalog(
        &self,
        service: &ServiceName,
    ) -> Result<Option<ServiceCatalog>, RepositoryError> {
        let snapshot = self.serving()?;
        let Some(entries) = snapshot.catalogue(service) else {
            return Ok(None);
        };
        Ok(Some(catalog_of(snapshot.as_ref(), service, entries)?))
    }
}

/// A [`PolicyView`] that hands out the published snapshot only while the pod is proven fresh, so a
/// reader that holds the view, such as the revocation sets, fails closed on a stale pod.
#[derive(Debug)]
pub struct FreshPolicyView {
    reads: SnapshotPolicyReads,
}

impl FreshPolicyView {
    /// The snapshot of `view` while `freshness` finds the pod fresh.
    #[must_use]
    pub const fn new(view: Arc<dyn PolicyView>, freshness: Arc<FreshnessState>) -> Self {
        Self {
            reads: SnapshotPolicyReads::new(view, freshness),
        }
    }
}

impl PolicyView for FreshPolicyView {
    fn current(&self) -> Option<Arc<dyn PolicySnapshot>> {
        self.reads.serving().ok()
    }
}

#[async_trait::async_trait]
impl PolicyReadRepository for SnapshotPolicyReads {
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

/// The epoch the snapshot stands for; the relay and catalogue epochs are not part of a snapshot.
fn epoch_of(snapshot: &dyn PolicySnapshot) -> Result<PolicyEpoch, SnapshotUnavailable> {
    PolicyEpoch::new(
        snapshot.version(),
        snapshot.digest(),
        snapshot.log_epoch(),
        RelayEpoch::ZERO,
        0,
    )
    .map_err(|_invalid| SnapshotUnavailable::Unusable("an epoch"))
}

fn policy_of(
    snapshot: &dyn PolicySnapshot,
    subject: &SubjectRef,
) -> Result<SubjectPolicy, SnapshotUnavailable> {
    let held = snapshot.assignments(subject);
    let assignments = held
        .iter()
        .map(role_assignment)
        .collect::<Result<Vec<_>, _>>()?;
    let role_sets = held
        .iter()
        .filter_map(|state| Some((state.role, snapshot.role_set(state.role)?.clone())))
        .collect();
    Ok(SubjectPolicy::new(
        epoch_of(snapshot)?,
        assignments,
        role_sets,
    ))
}

fn role_assignment(state: &AssignmentState) -> Result<RoleAssignment, SnapshotUnavailable> {
    let expires_at = state.expires_at_micros.map(instant).transpose()?;
    Ok(RoleAssignment::new(state.role, state.scope, expires_at))
}

/// The instant `micros` microseconds after 1970.
fn instant(micros: i64) -> Result<SystemTime, SnapshotUnavailable> {
    u64::try_from(micros)
        .ok()
        .and_then(|micros| SystemTime::UNIX_EPOCH.checked_add(Duration::from_micros(micros)))
        .ok_or(SnapshotUnavailable::Unusable("an instant before 1970"))
}

fn catalog_of(
    snapshot: &dyn PolicySnapshot,
    service: &ServiceName,
    entries: &[CatalogueEntryState],
) -> Result<ServiceCatalog, SnapshotUnavailable> {
    let mut operations = RestOperationSet::new();
    let mut fields = BTreeMap::new();
    for entry in entries {
        let key = PermissionKey::parse(&entry.key)
            .map_err(|_invalid| SnapshotUnavailable::Unusable("a permission key"))?;
        if key.service() != service {
            return Err(SnapshotUnavailable::Unusable(
                "a permission key of another service",
            ));
        }
        let flags = flags_of(entry);
        match key {
            PermissionKey::Rest {
                method, template, ..
            } => operations
                .insert(rest_operation(method, template.as_str(), flags)?)
                .map_err(|_duplicate| SnapshotUnavailable::Unusable("a duplicate operation"))?,
            PermissionKey::Gql {
                coordinate: GqlCoordinate::Field { type_name, field },
                ..
            } => {
                fields.insert(GraphQlCoordinate::new(type_name, field), flags);
            }
            PermissionKey::Gql { .. } | PermissionKey::Reserved(_) => {}
        }
    }
    Ok(ServiceCatalog::new(
        service.clone(),
        epoch_of(snapshot)?,
        vec![operations],
        type_graph(fields)?.into_iter().collect(),
    ))
}

fn rest_operation(
    method: iam_domain::HttpMethod,
    template: &str,
    flags: PermissionFlags,
) -> Result<RestOperation, SnapshotUnavailable> {
    let template = PathTemplate::from_stored(template)
        .ok_or(SnapshotUnavailable::Unusable("a path template"))?;
    Ok(RestOperation {
        method,
        template,
        label: None,
        flags,
    })
}

/// One graph over every coordinate; `None` when the catalogue has no GraphQL coordinate.
fn type_graph(
    coordinates: BTreeMap<GraphQlCoordinate, PermissionFlags>,
) -> Result<Option<GraphQlTypeGraph>, SnapshotUnavailable> {
    if coordinates.is_empty() {
        return Ok(None);
    }
    let return_type = GqlName::parse(PLACEHOLDER_RETURN_TYPE)
        .ok_or(SnapshotUnavailable::Unusable("a type name"))?;
    let fields = coordinates.into_iter().map(|(coordinate, flags)| {
        (
            coordinate,
            GraphQlField {
                return_type: return_type.clone(),
                flags,
            },
        )
    });
    GraphQlTypeGraph::new(fields, std::iter::empty())
        .map(Some)
        .map_err(|_invalid| SnapshotUnavailable::Unusable("a type graph"))
}

const fn flags_of(entry: &CatalogueEntryState) -> PermissionFlags {
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
