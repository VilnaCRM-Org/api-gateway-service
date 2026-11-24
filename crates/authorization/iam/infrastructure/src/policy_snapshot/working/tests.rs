//! The readers of the working state answer nothing for an entry whose state is not the one its
//! key names, instead of answering with the wrong kind of state.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use iam_domain::{
    HttpMethod, LogEpoch, PolicyDigestValue, PolicyHead, PolicyState, PolicyVersion, RatePolicyId,
    RoleId, RouteHost, RouteId, RouteMatcher, SessionId, StateKey, SubjectRef, UpstreamName,
};
use shared_domain::Uuid;

use super::{HostRoutes, Working};
use crate::policy_snapshot::shards::{Derived, Entry};

fn uuid(number: u32) -> Uuid {
    Uuid::parse(&format!("0192f6a0-0000-7000-8000-{number:012x}")).unwrap()
}

/// An entry that holds a head, which no key but the head names.
fn foreign_entry() -> Entry {
    Entry {
        version: PolicyVersion::new(1).unwrap(),
        state: PolicyState::Head(PolicyHead {
            version: PolicyVersion::new(1).unwrap(),
            digest: PolicyDigestValue::ZERO,
        }),
        hash: PolicyDigestValue::ZERO,
        derived: Derived::Nothing,
    }
}

fn working_with(key: StateKey) -> Working {
    let mut working = Working::empty(LogEpoch::ZERO);
    working.shards.insert(key, foreign_entry());
    working
}

/// Finds the same route for every request.
#[derive(Debug)]
struct AlwaysMatcher(RouteId);

impl RouteMatcher for AlwaysMatcher {
    fn find(&self, _method: HttpMethod, _path: &str) -> Option<RouteId> {
        Some(self.0)
    }
}

#[test]
fn a_matched_route_whose_entry_is_not_a_route_is_not_found() {
    let id = RouteId::from_uuid(uuid(1));
    let host = RouteHost::new("api.example.com").unwrap();
    let mut working = working_with(StateKey::Route(id));
    working.hosts = Arc::new(BTreeMap::from([(
        host.clone(),
        HostRoutes {
            ids: BTreeSet::from([id]),
            matcher: Arc::new(AlwaysMatcher(id)),
        },
    )]));

    assert!(working.route(&host, HttpMethod::Get, "/users").is_none());
}

#[test]
fn an_upstream_entry_that_is_not_an_upstream_is_not_found() {
    let name = UpstreamName::new("svc-1").unwrap();
    let working = working_with(StateKey::Upstream(name.clone()));

    assert!(working.upstream(&name).is_none());
}

#[test]
fn a_role_entry_without_compiled_grants_has_no_role_set() {
    let role = RoleId::from_uuid(uuid(1));
    let working = working_with(StateKey::Role(role));

    assert!(working.role_set(role).is_none());
}

#[test]
fn a_subject_entry_without_an_assignment_list_has_no_assignments() {
    let subject = SubjectRef::user(uuid(1));
    let working = working_with(StateKey::Subject(subject.clone()));

    assert_eq!(working.assignments(&subject), []);
}

#[test]
fn a_rate_policy_entry_that_is_not_a_rate_policy_is_not_found() {
    let id = RatePolicyId::from_uuid(uuid(1));
    let working = working_with(StateKey::RatePolicy(id));

    assert!(working.rate_policy(id).is_none());
}

#[test]
fn a_session_entry_that_is_not_a_revocation_does_not_revoke() {
    let session = SessionId::new("sid-1").unwrap();
    let working = working_with(StateKey::SessionRevocation(session.clone()));

    assert!(!working.session_revoked(&session));
}

#[test]
fn a_cutoff_entry_that_is_not_a_cutoff_is_not_found() {
    let user = uuid(1);

    assert!(
        working_with(StateKey::UserRevocation(user))
            .user_cutoff(user)
            .is_none()
    );
    assert!(
        working_with(StateKey::GlobalRevocation)
            .global_cutoff()
            .is_none()
    );
}
