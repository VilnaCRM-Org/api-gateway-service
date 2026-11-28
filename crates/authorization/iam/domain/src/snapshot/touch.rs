//! What a published policy version touched (Story 11.2, FR-61).
//!
//! The subjects, sessions, roles, catalogue services, routes and cut-offs whose records changed,
//! so that only the streams they can affect are decided again.

use std::collections::BTreeSet;

use crate::state::key::StateKey;
use crate::value_object::identifier::{RoleId, RouteId};
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::service_name::ServiceName;
use crate::value_object::session_id::SessionId;
use crate::value_object::subject::SubjectRef;

/// The records that one or several versions changed, by what a stream is bound to.
///
/// A user cut-off touches the user as a subject. A global cut-off, and a state that was replaced
/// as a whole, touch everything. An upstream, a rate policy and the head change no decision of an
/// open stream, so they touch nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyTouch {
    everything: bool,
    subjects: BTreeSet<SubjectRef>,
    sessions: BTreeSet<SessionId>,
    roles: BTreeSet<RoleId>,
    services: BTreeSet<ServiceName>,
    routes: BTreeSet<RouteId>,
}

impl PolicyTouch {
    /// A touch of nothing.
    #[must_use]
    pub fn nothing() -> Self {
        Self::default()
    }

    /// A touch of every stream: a global cut-off, or a state that was installed as a whole.
    #[must_use]
    pub fn everything() -> Self {
        Self {
            everything: true,
            ..Self::default()
        }
    }

    /// Notes that the record of `key` changed.
    pub fn note(&mut self, key: &StateKey) {
        match key {
            StateKey::Role(role) => {
                self.roles.insert(*role);
            }
            StateKey::Subject(subject) => {
                self.subjects.insert(subject.clone());
            }
            StateKey::CatalogueManifest(service) | StateKey::CatalogueChunk { service, .. } => {
                self.services.insert(service.clone());
            }
            StateKey::Route(route) => {
                self.routes.insert(*route);
            }
            StateKey::SessionRevocation(session) => {
                self.sessions.insert(session.clone());
            }
            StateKey::UserRevocation(user) => {
                self.subjects.insert(SubjectRef::user(*user));
            }
            StateKey::GlobalRevocation => self.everything = true,
            StateKey::Upstream(_) | StateKey::RatePolicy(_) | StateKey::Head => {}
        }
    }

    /// Adds what `other` touched.
    pub fn merge(&mut self, other: Self) {
        self.everything |= other.everything;
        self.subjects.extend(other.subjects);
        self.sessions.extend(other.sessions);
        self.roles.extend(other.roles);
        self.services.extend(other.services);
        self.routes.extend(other.routes);
    }

    /// Whether every stream is touched.
    #[must_use]
    pub const fn touches_everything(&self) -> bool {
        self.everything
    }

    /// Whether nothing is touched.
    #[must_use]
    pub fn is_nothing(&self) -> bool {
        !self.everything
            && self.subjects.is_empty()
            && self.sessions.is_empty()
            && self.roles.is_empty()
            && self.services.is_empty()
            && self.routes.is_empty()
    }

    /// The subjects whose assignments or cut-offs changed.
    #[must_use]
    pub const fn subjects(&self) -> &BTreeSet<SubjectRef> {
        &self.subjects
    }

    /// The sessions that were revoked.
    #[must_use]
    pub const fn sessions(&self) -> &BTreeSet<SessionId> {
        &self.sessions
    }

    /// The roles whose grants changed; the holders come from the reverse index of a snapshot.
    #[must_use]
    pub const fn roles(&self) -> &BTreeSet<RoleId> {
        &self.roles
    }

    /// The services whose catalogue changed.
    #[must_use]
    pub const fn services(&self) -> &BTreeSet<ServiceName> {
        &self.services
    }

    /// The routes that changed.
    #[must_use]
    pub const fn routes(&self) -> &BTreeSet<RouteId> {
        &self.routes
    }
}

/// One publication of the apply thread: the version now published and what the versions applied
/// since the previous publication touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyChange {
    /// The version that was published.
    pub version: PolicyVersion,
    /// What the versions since the previous publication touched.
    pub touch: PolicyTouch,
}

impl PolicyChange {
    /// Joins a later publication to this one: the version moves up and the touches add up.
    pub fn absorb(&mut self, later: Self) {
        self.version = self.version.max(later.version);
        self.touch.merge(later.touch);
    }
}

#[cfg(test)]
mod tests;
