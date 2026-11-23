use std::sync::Arc;

use iam_domain::{
    CatalogueChunk, CatalogueEntryState, CatalogueManifest, ChunkId, InvalidStateRecord, LogEpoch,
    PolicyDigestValue, PolicyHead, PolicyState, PolicyVersion, RoleId, RouteId, ServiceName,
    StateKey, StateRecordCodec, SubjectRef,
};
use shared_domain::Uuid;

use super::{Applier, catalogue_of, move_subject, roles_in, stored_route};
use crate::policy_snapshot::MatchitRouteTableCompiler;
use crate::policy_snapshot::builder::SnapshotBuildError;
use crate::policy_snapshot::shards::{Derived, Entry};
use crate::policy_snapshot::working::Working;
use crate::policy_state::sha256_policy_digest::Sha256PolicyDigest;

fn uuid(number: u32) -> Uuid {
    Uuid::parse(&format!("0192f6a0-0000-7000-8000-{number:012x}")).unwrap()
}

fn version() -> PolicyVersion {
    PolicyVersion::new(1).unwrap()
}

fn service() -> ServiceName {
    ServiceName::new("cat-1").unwrap()
}

fn head() -> PolicyState {
    PolicyState::Head(PolicyHead {
        version: version(),
        digest: PolicyDigestValue::ZERO,
    })
}

fn chunk() -> PolicyState {
    PolicyState::Chunk(CatalogueChunk {
        service: service(),
        entries: Vec::new(),
    })
}

fn entry(state: PolicyState) -> Entry {
    Entry {
        version: version(),
        state,
        hash: PolicyDigestValue::ZERO,
        derived: Derived::Nothing,
    }
}

/// Decodes every payload into the same state, whatever key it is read for.
#[derive(Debug)]
struct FixedCodec(PolicyState);

impl StateRecordCodec for FixedCodec {
    fn encode(&self, _state: &PolicyState) -> Result<String, InvalidStateRecord> {
        Ok(String::new())
    }

    fn decode(&self, _key: &StateKey, _payload: &str) -> Result<PolicyState, InvalidStateRecord> {
        Ok(self.0.clone())
    }

    fn entry_size(&self, _entry: &CatalogueEntryState) -> usize {
        0
    }
}

fn applier(decoded: PolicyState) -> Applier {
    Applier::new(
        Arc::new(FixedCodec(decoded)),
        Arc::new(Sha256PolicyDigest),
        Arc::new(MatchitRouteTableCompiler),
    )
}

#[test]
fn a_decoded_state_that_its_key_does_not_name_is_refused() {
    let key = StateKey::Role(RoleId::from_uuid(uuid(1)));

    let refused = applier(head()).decode(&key, version(), Some("{}"));

    assert!(matches!(
        refused,
        Err(SnapshotBuildError::InvalidRecord(
            InvalidStateRecord::Field { field: "state" }
        ))
    ));
}

#[test]
fn a_head_record_that_holds_another_state_is_a_missing_head() {
    let refused = applier(chunk()).head("{}");

    assert_eq!(refused, Err(SnapshotBuildError::MissingHead));
}

#[test]
fn a_route_entry_that_is_not_a_route_is_no_stored_route() {
    let id = RouteId::from_uuid(uuid(1));
    let mut working = Working::empty(LogEpoch::ZERO);
    working.shards.insert(StateKey::Route(id), entry(head()));

    assert!(stored_route(&working, id).is_none());
}

#[test]
fn a_manifest_entry_that_is_not_a_manifest_has_no_catalogue() {
    let mut working = Working::empty(LogEpoch::ZERO);
    working
        .shards
        .insert(StateKey::CatalogueManifest(service()), entry(head()));

    assert!(catalogue_of(&working, &service()).is_none());
}

#[test]
fn a_chunk_entry_that_is_not_a_chunk_has_no_catalogue() {
    let id = ChunkId::new("aa").unwrap();
    let mut working = Working::empty(LogEpoch::ZERO);
    working.shards.insert(
        StateKey::CatalogueManifest(service()),
        entry(PolicyState::Manifest(CatalogueManifest {
            service: service(),
            catalog_epoch: 1,
            chunks: vec![id.clone()],
        })),
    );
    working
        .shards
        .insert(StateKey::chunk(service(), id), entry(head()));

    assert!(catalogue_of(&working, &service()).is_none());
}

#[test]
fn a_state_that_is_not_a_subject_holds_no_role() {
    assert!(roles_in(&head()).is_empty());
}

#[test]
fn a_subject_whose_roles_stay_the_same_leaves_the_reverse_index_alone() {
    let mut working = Working::empty(LogEpoch::ZERO);
    let roles = std::collections::BTreeSet::from([RoleId::from_uuid(uuid(1))]);
    let before = Arc::clone(&working.role_subjects);

    move_subject(&mut working, &SubjectRef::user(uuid(2)), &roles, &roles);

    assert!(Arc::ptr_eq(&before, &working.role_subjects));
    assert!(working.role_subjects.is_empty());
}
