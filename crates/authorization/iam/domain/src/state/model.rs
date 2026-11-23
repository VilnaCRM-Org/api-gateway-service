//! The full state of each entity, as one record of the policy state topic carries it.
//!
//! The states are plain data: the order of every list is canonical, so that the same entity always
//! has the same state, and so the same encoded bytes and the same entity hash.

use crate::error::InvalidStateRecord;
use crate::rate_policy::RatePolicyParts;
use crate::rate_policy::fields::RatePolicyFields;
use crate::route::RouteParts;
use crate::route::fields::RouteFields;
use crate::state::key::{ChunkId, StateKey};
use crate::upstream::UpstreamParts;
use crate::upstream::settings::UpstreamSettings;
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::identifier::{RatePolicyId, RoleId, RouteId, UpstreamId};
use crate::value_object::policy_digest_value::PolicyDigestValue;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::role_kind::RoleKind;
use crate::value_object::service_name::ServiceName;
use crate::value_object::subject::SubjectRef;
use crate::value_object::upstream_name::UpstreamName;

/// One grant of a role: the text of its key or pattern, and whether it still takes part in
/// decisions (an orphaned grant does not).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GrantState {
    /// The permission key or wildcard pattern.
    pub key: String,
    /// Whether the grant is active.
    pub active: bool,
}

/// The state of a role that is not deleted: a deleted role is a tombstone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleState {
    /// The identifier.
    pub id: RoleId,
    /// The name.
    pub name: String,
    /// The description, when the role has one.
    pub description: Option<String>,
    /// Whether IAM or an administrator manages the role.
    pub kind: RoleKind,
    /// The optimistic-concurrency version of the role.
    pub version: EntityVersion,
    /// The grants.
    pub grants: Vec<GrantState>,
}

impl RoleState {
    /// The same state with its grants in canonical order.
    #[must_use]
    pub fn canonical(mut self) -> Self {
        self.grants.sort();
        self
    }
}

/// One assignment of a subject that is not revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AssignmentState {
    /// The assigned role.
    pub role: RoleId,
    /// The scope of the assignment.
    pub scope: AssignmentScope,
    /// When the assignment expires, in whole microseconds since 1970.
    pub expires_at_micros: Option<i64>,
}

/// The full assignment list of one subject; a subject without assignment is a tombstone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectState {
    /// The subject.
    pub subject: SubjectRef,
    /// The assignments.
    pub assignments: Vec<AssignmentState>,
}

impl SubjectState {
    /// The same state with its assignments in canonical order.
    #[must_use]
    pub fn canonical(mut self) -> Self {
        self.assignments.sort();
        self
    }
}

/// One active entry of a service catalogue.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CatalogueEntryState {
    /// The permission key.
    pub key: String,
    /// Whether a wildcard never covers the key.
    pub sensitive: bool,
    /// Whether every check of the key is audited.
    pub audit_always: bool,
}

/// One content-addressed chunk of the entries of a service catalogue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogueChunk {
    /// The service.
    pub service: ServiceName,
    /// The entries, in key order.
    pub entries: Vec<CatalogueEntryState>,
}

/// The chunks that make the catalogue of a service; a snapshot applies the catalogue only when the
/// manifest and every chunk of it are present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogueManifest {
    /// The service.
    pub service: ServiceName,
    /// The catalogue epoch the manifest was written at.
    pub catalog_epoch: i64,
    /// The chunks, in the order of their entries.
    pub chunks: Vec<ChunkId>,
}

/// The state of an upstream that is not deleted: a deleted upstream is a tombstone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamState {
    /// The identifier.
    pub id: UpstreamId,
    /// The name, which the key of the record carries as well.
    pub name: UpstreamName,
    /// The settings.
    pub settings: UpstreamSettings,
    /// Whether IAM manages the upstream.
    pub system: bool,
    /// The optimistic-concurrency version of the upstream.
    pub version: EntityVersion,
}

impl UpstreamState {
    /// The state of a stored upstream.
    #[must_use]
    pub fn of(parts: &UpstreamParts) -> Self {
        Self {
            id: parts.id,
            name: parts.name.clone(),
            settings: parts.settings.clone(),
            system: parts.system,
            version: parts.version,
        }
    }
}

/// The state of a route that is not deleted: a deleted route is a tombstone. The rate policies
/// stay in the order they apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteState {
    /// The identifier.
    pub id: RouteId,
    /// The configuration.
    pub fields: RouteFields,
    /// Whether IAM manages the route.
    pub system: bool,
    /// The optimistic-concurrency version of the route.
    pub version: EntityVersion,
}

impl RouteState {
    /// The state of a stored route.
    #[must_use]
    pub fn of(parts: &RouteParts) -> Self {
        Self {
            id: parts.id,
            fields: parts.fields.clone(),
            system: parts.system,
            version: parts.version,
        }
    }
}

/// The state of a rate policy that is not deleted: a deleted rate policy is a tombstone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatePolicyState {
    /// The identifier.
    pub id: RatePolicyId,
    /// The configuration.
    pub fields: RatePolicyFields,
    /// The optimistic-concurrency version of the rate policy.
    pub version: EntityVersion,
}

impl RatePolicyState {
    /// The state of a stored rate policy.
    #[must_use]
    pub fn of(parts: &RatePolicyParts) -> Self {
        Self {
            id: parts.id,
            fields: parts.fields.clone(),
            version: parts.version,
        }
    }
}

/// The version and the digest that a versioned transaction ended with: the last record of the
/// version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyHead {
    /// The policy version.
    pub version: PolicyVersion,
    /// The digest of the whole policy state at that version.
    pub digest: PolicyDigestValue,
}

/// The state that one record carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyState {
    /// A role.
    Role(RoleState),
    /// The assignments of a subject.
    Subject(SubjectState),
    /// The manifest of a service catalogue.
    Manifest(CatalogueManifest),
    /// A chunk of a service catalogue.
    Chunk(CatalogueChunk),
    /// An upstream.
    Upstream(UpstreamState),
    /// A route.
    Route(RouteState),
    /// A rate policy.
    RatePolicy(RatePolicyState),
    /// The head of a version.
    Head(PolicyHead),
}

impl PolicyState {
    /// Whether this state is the one that `key` names.
    #[must_use]
    pub fn belongs_to(&self, key: &StateKey) -> bool {
        match (self, key) {
            (Self::Role(role), StateKey::Role(id)) => role.id == *id,
            (Self::Subject(state), StateKey::Subject(subject)) => state.subject == *subject,
            (Self::Manifest(manifest), StateKey::CatalogueManifest(service)) => {
                manifest.service == *service
            }
            (Self::Chunk(chunk), StateKey::CatalogueChunk { service, .. }) => {
                chunk.service == *service
            }
            (Self::Upstream(upstream), StateKey::Upstream(name)) => upstream.name == *name,
            (Self::Route(route), StateKey::Route(id)) => route.id == *id,
            (Self::RatePolicy(policy), StateKey::RatePolicy(id)) => policy.id == *id,
            (Self::Head(_), StateKey::Head) => true,
            _ => false,
        }
    }
}

/// One record of the policy state topic: a key and its full state, or a tombstone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateRecord {
    key: StateKey,
    state: Option<PolicyState>,
}

impl StateRecord {
    /// A record whose state is the one the key names, or a tombstone when `state` is `None`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidStateRecord::Field`] when the state is not the one that the key names.
    pub fn new(key: StateKey, state: Option<PolicyState>) -> Result<Self, InvalidStateRecord> {
        if state.as_ref().is_some_and(|state| !state.belongs_to(&key)) {
            return Err(InvalidStateRecord::Field { field: "state" });
        }
        Ok(Self { key, state })
    }

    /// The key.
    #[must_use]
    pub const fn key(&self) -> &StateKey {
        &self.key
    }

    /// The full state, or `None` for a tombstone.
    #[must_use]
    pub const fn state(&self) -> Option<&PolicyState> {
        self.state.as_ref()
    }

    /// Whether the record deletes its key.
    #[must_use]
    pub const fn is_tombstone(&self) -> bool {
        self.state.is_none()
    }
}

#[cfg(test)]
mod tests;
