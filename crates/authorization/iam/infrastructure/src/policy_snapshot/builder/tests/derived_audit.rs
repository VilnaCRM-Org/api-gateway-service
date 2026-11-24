//! The check of the derived structures against the raw records, through the builder.

use std::collections::BTreeSet;
use std::sync::Arc;

use iam_domain::{CHECK_GROUPS, DerivedStateAudit as _, PolicyState, RouteHost, RouteId, StateKey};
use test_support::log::LogRecorder;

use super::support::{
    Rig, role, role_key, route, route_id, route_key, subject, subject_key, upstream, version,
};
use super::{ApplyOutcome, RawEntry};
use crate::policy_snapshot::fnv::{SHARD_COUNT, shard_of};

/// A policy with roles, subjects that share and differ in their assignments, routes of two hosts
/// and an upstream.
fn filled() -> Rig {
    let mut rig = Rig::new();
    let mut edits = vec![
        role(1, &["rest:cat-0:GET /users"]),
        role(2, &["rest:cat-0:POST /users", "rest:cat-0:GET /orders"]),
        upstream(1, 8080),
        route(1, "api.example.com"),
        route(2, "api.example.com"),
        route(3, "other.example.com"),
    ];
    edits.extend((1..=40).map(|number| {
        subject(
            number,
            &[number.checked_rem(2).unwrap_or(0).saturating_add(1)],
        )
    }));
    rig.apply(edits);
    rig
}

fn audit_all(rig: &mut Rig) -> Result<usize, iam_domain::DerivedMismatch> {
    (0..CHECK_GROUPS).try_fold(0_usize, |total, group| {
        rig.builder
            .audit_group(group)
            .map(|checked| total.saturating_add(checked))
    })
}

#[test]
fn sixteen_groups_cover_every_shard_exactly_once() {
    let mut rig = filled();

    assert_eq!(audit_all(&mut rig), Ok(SHARD_COUNT));
}

#[test]
fn an_incrementally_built_snapshot_matches_the_raw_records() {
    let mut rig = filled();
    rig.apply(vec![
        subject(3, &[2]),
        subject(4, &[]),
        role(1, &["rest:cat-0:DELETE /users"]),
        route(2, "other.example.com"),
    ]);

    assert_eq!(audit_all(&mut rig), Ok(SHARD_COUNT));
}

#[test]
fn a_rebuilt_snapshot_matches_the_raw_records() {
    let mut rig = Rig::new();
    let entries: Vec<RawEntry> = [role(1, &["rest:cat-0:GET /users"]), subject(1, &[1])]
        .iter()
        .map(|(key, state)| RawEntry {
            key: key.clone(),
            version: version(1),
            payload: rig.encode(state.as_ref().unwrap()),
        })
        .collect();
    rig.builder
        .rebuild(&entries, version(1), iam_domain::LogEpoch::new(1).unwrap())
        .unwrap();

    assert_eq!(audit_all(&mut rig), Ok(SHARD_COUNT));
}

#[test]
fn a_corrupt_compiled_role_set_is_found_in_the_group_of_its_shard() {
    let mut rig = filled();
    let key = role_key(2);
    let shard = shard_of(&key);

    assert!(rig.builder.corrupt_derived(&key));

    let mismatch = rig.builder.audit_group(shard % CHECK_GROUPS).unwrap_err();
    assert_eq!(mismatch.shard, shard);
    assert_ne!(mismatch.rebuilt, mismatch.held);
}

#[test]
fn a_corrupt_assignment_list_is_found_in_the_group_of_its_shard() {
    let mut rig = filled();
    let key = subject_key(5);
    let shard = shard_of(&key);

    assert!(rig.builder.corrupt_derived(&key));

    let mismatch = rig.builder.audit_group(shard % CHECK_GROUPS).unwrap_err();
    assert_eq!(mismatch.shard, shard);
}

#[test]
fn only_the_group_of_the_corrupt_shard_fails() {
    let mut rig = filled();
    let key = role_key(2);
    let shard = shard_of(&key);
    rig.builder.corrupt_derived(&key);

    for group in (0..CHECK_GROUPS).filter(|group| *group != shard % CHECK_GROUPS) {
        assert!(rig.builder.audit_group(group).is_ok(), "group {group}");
    }
}

#[test]
fn corrupting_a_structure_changes_the_derived_hash_and_the_published_snapshot() {
    let mut rig = filled();
    let before = rig.snapshot().derived_hash();
    let digest = rig.snapshot().digest();

    rig.builder.corrupt_derived(&role_key(1));

    let after = rig.snapshot();
    assert_ne!(after.derived_hash(), before);
    assert_eq!(after.digest(), digest, "the raw records did not change");
}

#[test]
fn a_key_that_is_not_live_cannot_be_corrupted() {
    let mut rig = filled();
    let published = rig.snapshot().derived_hash();

    assert!(!rig.builder.corrupt_derived(&role_key(99)));
    assert!(!rig.builder.corrupt_derived(&route_key(99)));

    assert_eq!(rig.snapshot().derived_hash(), published);
}

#[test]
fn two_builders_with_the_same_history_agree_on_the_derived_hash() {
    let (first, second) = (filled(), filled());

    assert_eq!(
        first.snapshot().derived_hash(),
        second.snapshot().derived_hash()
    );
    assert_eq!(first.snapshot().digest(), second.snapshot().digest());
}

#[test]
fn applying_a_further_version_keeps_the_structures_consistent() {
    let mut rig = filled();

    let outcome = rig.apply(vec![subject(41, &[1, 2])]);

    assert!(matches!(outcome, ApplyOutcome::Applied { .. }));
    assert_eq!(audit_all(&mut rig), Ok(SHARD_COUNT));
}

/// The route ids that the table of `host` lists, for a test to corrupt.
fn listed_ids<'a>(rig: &'a mut Rig, host: &str) -> &'a mut BTreeSet<RouteId> {
    let host = RouteHost::new(host).unwrap();
    &mut Arc::make_mut(&mut rig.builder.working.hosts)
        .get_mut(&host)
        .unwrap()
        .ids
}

#[test]
fn a_host_that_lists_a_route_nobody_holds_is_a_mismatch() {
    let mut rig = filled();

    listed_ids(&mut rig, "api.example.com").insert(route_id(99));

    assert!(audit_all(&mut rig).is_err());
}

#[test]
fn a_host_that_lists_an_entry_that_is_no_route_is_a_mismatch() {
    let mut rig = filled();
    let not_a_route = rig
        .builder
        .working
        .shards
        .get(&role_key(1))
        .unwrap()
        .clone();
    rig.builder
        .working
        .shards
        .insert(StateKey::Route(route_id(98)), not_a_route);

    listed_ids(&mut rig, "api.example.com").insert(route_id(98));

    assert!(audit_all(&mut rig).is_err());
}

#[test]
fn a_host_that_lists_the_route_of_another_host_is_a_mismatch() {
    let mut rig = filled();

    listed_ids(&mut rig, "api.example.com").insert(route_id(3));

    assert!(audit_all(&mut rig).is_err());
}

#[test]
fn a_record_that_can_no_longer_be_derived_is_a_mismatch_in_its_shard() {
    let mut rig = filled();
    let key = role_key(1);
    let mut entry = rig.builder.working.shards.remove(&key).unwrap();
    if let PolicyState::Role(role) = &mut entry.state {
        role.grants.clear();
        role.grants.push(iam_domain::GrantState {
            key: "not a grant".to_owned(),
            active: true,
        });
    }
    rig.builder.working.shards.insert(key.clone(), entry);

    let mismatch = rig
        .builder
        .audit_group(shard_of(&key) % CHECK_GROUPS)
        .unwrap_err();

    assert_eq!(mismatch.shard, shard_of(&key));
}

#[test]
fn a_publication_reports_the_version_the_digest_and_the_derived_hash() {
    let (recorder, _guard) = LogRecorder::install();
    let mut rig = Rig::new();

    rig.apply(vec![role(1, &["rest:cat-0:GET /users"])]);

    let snapshot = rig.snapshot();
    let lines = recorder.lines();
    let metrics: Vec<&str> = lines
        .iter()
        .filter_map(|line| line.field("metric"))
        .collect();
    assert_eq!(
        metrics,
        [
            "policy_applied_version",
            "policy_digest_info",
            "policy_derived_hash_info"
        ]
    );
    assert_eq!(
        lines[1].field("digest"),
        Some(snapshot.digest().to_hex().as_str())
    );
    assert_eq!(
        lines[2].field("derived_hash"),
        Some(snapshot.derived_hash().to_hex().as_str())
    );
}
