use std::time::Duration;

use iam_domain::{
    FenceVerdict, HttpMethod, LogEpoch, PolicyDigestValue, RecordVerdict, RelayEpoch, RouteHost,
};
use rand::RngExt as _;
use test_support::seed::TestRng;

use super::*;

mod history;
mod size;
mod support;

use support::route_with_pattern;
use support::{
    Rig, catalogue, manifest_key, rate_policy, role, role_key, route, route_id, route_key, subject,
    subject_ref, upstream, upstream_id, upstream_key, version,
};

fn host() -> RouteHost {
    RouteHost::new("api.example.com").unwrap()
}

fn shuffle<T>(items: &mut [T], rng: &mut TestRng) {
    for index in (1..items.len()).rev() {
        items.swap(index, rng.rng().random_range(0..=index));
    }
}

#[test]
fn a_version_is_applied_only_when_all_its_records_are_present_in_any_order() {
    let mut rng = TestRng::from_env();
    let mut rig = Rig::new();
    let records = rig.write(vec![
        role(1, &["rest:cat-0:GET /users"]),
        subject(1, &[1]),
        upstream(1, 8080),
        rate_policy(1, 100),
    ]);
    assert_eq!(records.len(), 5);
    let mut offered = records.clone();
    offered.extend(records.iter().take(3).cloned());
    shuffle(&mut offered, &mut rng);

    let outcomes: Vec<_> = offered
        .into_iter()
        .map(|record| rig.builder.offer(record))
        .collect();

    let applied = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, ApplyOutcome::Applied { .. }))
        .count();
    let refused = outcomes
        .iter()
        .filter(|outcome| {
            matches!(
                outcome,
                ApplyOutcome::Rejected(_) | ApplyOutcome::Fenced(_) | ApplyOutcome::Malformed
            )
        })
        .count();
    assert_eq!(applied, 1);
    assert_eq!(refused, 0);
    assert_eq!(rig.builder.applied_version(), version(1));
    assert_eq!(rig.snapshot().version(), version(1));
    assert_eq!(rig.builder.digest(), rig.digest);
}

#[test]
fn a_version_with_a_missing_record_is_not_applied() {
    let mut rig = Rig::new();
    let mut records = rig.write(vec![role(1, &["rest:cat-0:GET /users"]), subject(1, &[1])]);
    records.remove(1);

    let outcome = rig.offer_all(records);

    assert_eq!(outcome, ApplyOutcome::Pending { missing: Some(1) });
    assert_eq!(rig.builder.applied_version(), version(0));
    assert!(rig.cell.load().is_none());
}

#[test]
fn a_gap_is_reported_and_the_published_snapshot_stays() {
    let mut rig = Rig::new();
    rig.apply(vec![role(1, &["rest:cat-0:GET /users"])]);
    let skipped = rig.write(vec![role(2, &["rest:cat-0:POST /users"])]);
    drop(skipped);
    let third = rig.write(vec![role(3, &["gql:cat-0:Query.users"])]);

    let outcome = rig.offer_all(third);

    assert_eq!(
        outcome,
        ApplyOutcome::Gap {
            expected: version(2)
        }
    );
    assert_eq!(rig.snapshot().version(), version(1));
    assert_eq!(rig.builder.applied_version(), version(1));
}

#[test]
fn a_record_of_an_applied_version_is_ignored_or_fences() {
    let mut rig = Rig::new();
    rig.relay_epoch = 2;
    let records = rig.write(vec![role(1, &["rest:cat-0:GET /users"])]);
    rig.offer_all(records.clone());
    let head = records.last().unwrap().clone();

    let mut conflicting = head.clone();
    conflicting.digest_after = PolicyDigestValue::from_bytes([9; PolicyDigestValue::LENGTH]);
    let mut lower_log = head.clone();
    lower_log.log_epoch = LogEpoch::ZERO;
    let mut lower_relay = head.clone();
    lower_relay.relay_epoch = RelayEpoch::new(1).unwrap();

    assert_eq!(
        rig.builder.offer(head),
        ApplyOutcome::Ignored(RecordVerdict::AlreadyApplied)
    );
    assert_eq!(
        rig.builder.offer(conflicting),
        ApplyOutcome::Fenced(FenceVerdict::ConflictingContent)
    );
    assert_eq!(
        rig.builder.offer(lower_log),
        ApplyOutcome::Fenced(FenceVerdict::LowerLogEpoch)
    );
    assert_eq!(
        rig.builder.offer(lower_relay),
        ApplyOutcome::Ignored(RecordVerdict::LowerRelayEpoch)
    );
    assert_eq!(rig.snapshot().version(), version(1));
}

#[test]
fn a_digest_that_differs_from_the_incremental_digest_is_not_published() {
    let mut rig = Rig::new();
    let wrong = PolicyDigestValue::from_bytes([7; PolicyDigestValue::LENGTH]);
    let records = rig.write_after(vec![role(1, &["rest:cat-0:GET /users"])], wrong);

    let outcome = rig.offer_all(records);

    let ApplyOutcome::Rejected(SnapshotBuildError::DigestMismatch { version: at, .. }) = outcome
    else {
        panic!("expected a digest mismatch, got {outcome:?}");
    };
    assert_eq!(at, version(1));
    assert_eq!(rig.builder.applied_version(), version(0));
    assert!(rig.cell.load().is_none());
    assert_eq!(rig.builder.digest(), PolicyDigestValue::ZERO);
}

#[test]
fn a_rejected_version_leaves_the_applied_state_untouched() {
    let mut rig = Rig::new();
    rig.apply(vec![role(1, &["rest:cat-0:GET /users"])]);
    let before = rig.builder.digest();
    let wrong = PolicyDigestValue::from_bytes([7; PolicyDigestValue::LENGTH]);
    let records = rig.write_after(vec![role(2, &["rest:cat-0:POST /users"])], wrong);

    rig.offer_all(records);

    assert_eq!(rig.builder.digest(), before);
    assert_eq!(rig.builder.applied_version(), version(1));
    assert!(rig.snapshot().role_set(role_id(2)).is_none());
}

fn role_id(number: u32) -> iam_domain::RoleId {
    iam_domain::RoleId::from_uuid(support::uuid(number))
}

#[test]
fn fifty_versions_within_the_interval_publish_once_at_a_version_boundary() {
    let mut rig = Rig::new();
    let mut published = 0;
    let mut earlier = None;
    for port in 1..=50_i64 {
        rig.clock.advance(Duration::from_micros(50));
        if let ApplyOutcome::Applied { published: yes, .. } =
            rig.apply(vec![upstream(1, 8_000 + port)])
        {
            published += usize::from(yes);
        }
        if port == 1 {
            earlier = Some(rig.snapshot());
        }
    }
    let copies = rig.builder.working.shards.copies();

    assert_eq!(published, 1);
    assert_eq!(rig.snapshot().version(), version(1));
    assert_eq!(copies, 1, "the shard is cloned once for the whole interval");
    assert!(rig.builder.flush());
    assert_eq!(rig.snapshot().version(), version(50));
    let earlier = earlier.unwrap();
    assert_eq!(earlier.version(), version(1));
    let name = iam_domain::UpstreamName::new("svc-1").unwrap();
    assert_eq!(earlier.upstream(&name).unwrap().settings.port(), 8_001);
    assert_eq!(
        rig.snapshot().upstream(&name).unwrap().settings.port(),
        8_050
    );
}

#[test]
fn publication_follows_the_boot_clock_alone() {
    let mut rig = Rig::new();
    let publish = |rig: &mut Rig, number: i64, after: Duration| {
        rig.clock.advance(after);
        let outcome = rig.apply(vec![upstream(1, 8_000 + number)]);
        let ApplyOutcome::Applied { published, .. } = outcome else {
            panic!("expected an applied version, got {outcome:?}");
        };
        published
    };

    assert!(publish(&mut rig, 1, Duration::ZERO));
    assert!(!publish(&mut rig, 2, Duration::from_millis(4)));
    assert!(publish(&mut rig, 3, Duration::from_millis(1)));
    assert!(!publish(&mut rig, 4, Duration::from_micros(10)));
    rig.clock.jump(Duration::from_secs(3_600));
    assert!(publish(&mut rig, 5, Duration::ZERO));
}

#[test]
fn a_tick_publishes_what_the_interval_held_back() {
    let mut rig = Rig::new();
    rig.apply(vec![upstream(1, 8_001)]);
    rig.apply(vec![upstream(1, 8_002)]);
    assert!(!rig.builder.tick());
    assert_eq!(rig.snapshot().version(), version(1));

    rig.clock.advance(Duration::from_millis(5));

    assert!(rig.builder.tick());
    assert_eq!(rig.snapshot().version(), version(2));
    assert!(!rig.builder.tick());
    assert!(!rig.builder.flush());
}

#[test]
fn roles_subjects_and_the_reverse_index_follow_the_records() {
    let mut rig = Rig::new();
    rig.apply(vec![
        role(1, &["rest:cat-0:GET /users", "rest:cat-0:*"]),
        subject(1, &[1]),
        subject(2, &[1]),
    ]);
    rig.builder.flush();

    let snapshot = rig.snapshot();
    assert_eq!(snapshot.role_set(role_id(1)).unwrap().key_count(), 1);
    assert_eq!(snapshot.assignments(&subject_ref(1)).len(), 1);
    assert_eq!(
        snapshot.subjects_of_role(role_id(1)),
        vec![subject_ref(1), subject_ref(2)]
    );

    rig.apply(vec![subject(1, &[]), role(1, &[])]);
    rig.builder.flush();

    let snapshot = rig.snapshot();
    assert_eq!(snapshot.assignments(&subject_ref(1)), []);
    assert_eq!(snapshot.subjects_of_role(role_id(1)), vec![subject_ref(2)]);
    assert!(snapshot.role_set(role_id(1)).unwrap().is_empty());
}

#[test]
fn a_tombstone_deletes_the_key() {
    let mut rig = Rig::new();
    rig.apply(vec![
        role(1, &["rest:cat-0:GET /users"]),
        upstream(1, 8_080),
    ]);
    rig.apply(vec![(role_key(1), None), (upstream_key(1), None)]);
    rig.builder.flush();

    let snapshot = rig.snapshot();
    assert!(snapshot.role_set(role_id(1)).is_none());
    assert!(snapshot.upstream_by_id(upstream_id(1)).is_none());
    assert_eq!(rig.builder.digest(), rig.digest);
    assert_eq!(rig.builder.digest(), PolicyDigestValue::ZERO);
}

#[test]
fn routes_are_matched_per_host_and_follow_changes() {
    let mut rig = Rig::new();
    rig.apply(vec![
        route(1, "api.example.com"),
        route(2, "other.example.com"),
    ]);
    rig.builder.flush();

    let snapshot = rig.snapshot();
    let found = snapshot.route(&host(), HttpMethod::Get, "/r1/42").unwrap();
    assert_eq!(found.id, route_id(1));
    assert!(snapshot.route(&host(), HttpMethod::Get, "/r2/42").is_none());
    assert!(
        snapshot
            .route(&host(), HttpMethod::Delete, "/r1/42")
            .is_none()
    );

    rig.apply(vec![route(1, "other.example.com")]);
    rig.apply(vec![(route_key(2), None)]);
    rig.builder.flush();

    let snapshot = rig.snapshot();
    assert!(snapshot.route(&host(), HttpMethod::Get, "/r1/42").is_none());
    let other = RouteHost::new("other.example.com").unwrap();
    assert_eq!(
        snapshot
            .route(&other, HttpMethod::Get, "/r1/42")
            .unwrap()
            .id,
        route_id(1)
    );
    assert!(snapshot.route(&other, HttpMethod::Get, "/r2/42").is_none());
}

#[test]
fn upstreams_and_rate_policies_are_read_by_identifier() {
    let mut rig = Rig::new();
    rig.apply(vec![upstream(1, 8_080), rate_policy(1, 100)]);
    rig.builder.flush();

    let snapshot = rig.snapshot();
    assert_eq!(
        snapshot.upstream_by_id(upstream_id(1)).unwrap().id,
        upstream_id(1)
    );
    let policy_id = iam_domain::RatePolicyId::from_uuid(support::uuid(4_001));
    assert_eq!(snapshot.rate_policy(policy_id).unwrap().id, policy_id);
}

#[test]
fn revocations_and_cutoffs_are_read_from_the_snapshot() {
    use iam_domain::{
        GlobalRevocationState, PolicyState, SessionId, SessionRevocationState, StateKey,
        UserRevocationState,
    };

    let session = SessionId::new("sid-1").unwrap();
    let user = support::uuid(5_001);
    let user_cutoff = UserRevocationState {
        user,
        tokens_valid_after_micros: 7_000_000,
        prune_after_micros: 9_000_000,
    };
    let global = GlobalRevocationState {
        tokens_valid_after_micros: 3_000_000,
    };
    let mut rig = Rig::new();
    rig.apply(vec![
        (
            StateKey::SessionRevocation(session.clone()),
            Some(PolicyState::SessionRevocation(SessionRevocationState {
                session: session.clone(),
                user,
                revoked_at_micros: 1_000_000,
                prune_after_micros: 9_000_000,
            })),
        ),
        (
            StateKey::UserRevocation(user),
            Some(PolicyState::UserRevocation(user_cutoff.clone())),
        ),
        (
            StateKey::GlobalRevocation,
            Some(PolicyState::GlobalRevocation(global.clone())),
        ),
    ]);
    rig.builder.flush();

    let snapshot = rig.snapshot();
    assert!(snapshot.session_revoked(&session));
    assert!(!snapshot.session_revoked(&SessionId::new("sid-2").unwrap()));
    assert_eq!(snapshot.user_cutoff(user), Some(&user_cutoff));
    assert_eq!(snapshot.user_cutoff(support::uuid(5_002)), None);
    assert_eq!(snapshot.global_cutoff(), Some(&global));
}

#[test]
fn a_catalogue_is_applied_only_when_its_manifest_and_every_chunk_are_present() {
    let mut rig = Rig::new();
    let (manifest, chunk) = catalogue(1, "00ff", &["rest:cat-1:GET /a", "rest:cat-1:GET /b"]);
    rig.apply(vec![manifest]);
    rig.builder.flush();
    assert!(rig.snapshot().catalogue(&support::service(1)).is_none());

    rig.apply(vec![chunk]);
    rig.builder.flush();

    let snapshot = rig.snapshot();
    assert_eq!(snapshot.catalogue(&support::service(1)).unwrap().len(), 2);
    rig.apply(vec![(manifest_key(1), None)]);
    rig.builder.flush();
    assert!(rig.snapshot().catalogue(&support::service(1)).is_none());
}

#[test]
fn a_record_that_cannot_be_decoded_rejects_the_version() {
    let mut rig = Rig::new();
    let mut records = rig.write(vec![role(1, &["rest:cat-0:GET /users"])]);
    records.first_mut().unwrap().payload = Some("{not json".to_owned());

    let outcome = rig.offer_all(records);

    assert!(matches!(
        outcome,
        ApplyOutcome::Rejected(SnapshotBuildError::InvalidRecord(_))
    ));
    assert_eq!(rig.builder.applied_version(), version(0));
}

#[test]
fn a_version_that_does_not_end_with_its_head_is_rejected() {
    let mut rig = Rig::new();
    let mut records = rig.write(vec![role(1, &["rest:cat-0:GET /users"])]);
    let last = records.len() - 1;
    records.swap(0, last);
    for (index, record) in records.iter_mut().enumerate() {
        record.seq = u32::try_from(index + 1).unwrap();
    }

    let outcome = rig.offer_all(records);

    assert_eq!(
        outcome,
        ApplyOutcome::Rejected(SnapshotBuildError::MissingHead)
    );
}

#[test]
fn a_record_with_invalid_framing_is_malformed() {
    let mut rig = Rig::new();
    let mut records = rig.write(vec![role(1, &["rest:cat-0:GET /users"])]);
    let mut stray = records.remove(0);
    stray.count = 99;
    rig.builder.offer(records.remove(0));

    assert_eq!(rig.builder.offer(stray), ApplyOutcome::Malformed);
}

#[test]
fn a_record_of_a_held_position_with_other_content_fences() {
    let mut rig = Rig::new();
    let mut records = rig.write(vec![role(1, &["rest:cat-0:GET /users"])]);
    let first = records.remove(0);
    let mut rival = first.clone();
    rival.digest_after = PolicyDigestValue::from_bytes([7; PolicyDigestValue::LENGTH]);
    rig.builder.offer(first);

    assert_eq!(
        rig.builder.offer(rival),
        ApplyOutcome::Fenced(FenceVerdict::ConflictingContent)
    );
    assert_eq!(rig.builder.applied_version(), version(0));
}

#[test]
fn a_head_of_another_version_is_rejected() {
    let mut rig = Rig::new();
    let mut records = rig.write(vec![role(1, &["rest:cat-0:GET /users"])]);
    let head = records.last_mut().unwrap();
    head.payload = Some(
        rig.encode(&iam_domain::PolicyState::Head(iam_domain::PolicyHead {
            version: version(2),
            digest: head.digest_after,
        })),
    );

    let outcome = rig.offer_all(records);

    assert_eq!(
        outcome,
        ApplyOutcome::Rejected(SnapshotBuildError::MissingHead)
    );
    assert_eq!(rig.builder.applied_version(), version(0));
}

#[test]
fn a_head_whose_digest_differs_from_its_record_is_rejected() {
    let mut rig = Rig::new();
    let mut records = rig.write(vec![role(1, &["rest:cat-0:GET /users"])]);
    let wrong = PolicyDigestValue::from_bytes([7; PolicyDigestValue::LENGTH]);
    let head = records.last_mut().unwrap();
    let computed = head.digest_after;
    head.digest_after = wrong;

    let outcome = rig.offer_all(records);

    assert_eq!(
        outcome,
        ApplyOutcome::Rejected(SnapshotBuildError::DigestMismatch {
            version: version(1),
            expected: wrong,
            computed,
        })
    );
    assert_eq!(rig.builder.applied_version(), version(0));
}

#[test]
fn the_snapshot_reports_the_digest_and_the_log_epoch_of_its_version() {
    let mut rig = Rig::new();
    rig.apply(vec![role(1, &["rest:cat-0:GET /users"]), subject(1, &[1])]);
    rig.builder.flush();

    let snapshot = rig.snapshot();

    assert_eq!(snapshot.digest(), rig.digest);
    assert_eq!(snapshot.digest(), rig.builder.digest());
    assert_eq!(snapshot.log_epoch(), LogEpoch::new(1).unwrap());
    assert_ne!(snapshot.derived_hash(), PolicyDigestValue::ZERO);
}

#[test]
fn a_full_rebuild_replaces_the_state_and_publishes() {
    let mut source = Rig::new();
    source.apply(vec![
        role(1, &["rest:cat-0:GET /users"]),
        subject(1, &[1]),
        upstream(1, 8_080),
    ]);
    let entries = history::raw_entries(&source);
    let mut target = Rig::new();

    target
        .builder
        .rebuild(&entries, version(1), LogEpoch::new(1).unwrap())
        .unwrap();

    assert_eq!(target.builder.digest(), source.digest);
    assert_eq!(target.snapshot().version(), version(1));
    assert_eq!(
        target.snapshot().subjects_of_role(role_id(1)),
        vec![subject_ref(1)]
    );
}

#[test]
fn a_rebuild_with_an_invalid_entry_changes_nothing() {
    let mut rig = Rig::new();
    rig.apply(vec![role(1, &["rest:cat-0:GET /users"])]);
    let entry = RawEntry {
        key: role_key(2),
        version: version(1),
        payload: "{not json".to_owned(),
    };

    let result = rig.builder.rebuild(&[entry], version(5), LogEpoch::ZERO);

    assert!(result.is_err());
    assert_eq!(rig.builder.applied_version(), version(1));
}

#[test]
fn a_verified_rebuild_publishes_a_state_that_hashes_to_the_head() {
    let mut source = Rig::new();
    source.apply(vec![role(1, &["rest:cat-0:GET /users"]), subject(1, &[1])]);
    let entries = history::raw_entries(&source);
    let mut target = Rig::new();

    target
        .builder
        .rebuild_verified(&entries, version(1), (LogEpoch::ZERO, source.digest))
        .unwrap();

    assert_eq!(target.builder.digest(), source.digest);
    assert_eq!(target.snapshot().version(), version(1));
}

#[test]
fn a_verified_rebuild_refuses_a_state_that_does_not_hash_to_the_head() {
    use iam_domain::PolicyView as _;

    let mut source = Rig::new();
    source.apply(vec![role(1, &["rest:cat-0:GET /users"])]);
    let entries = history::raw_entries(&source);
    let mut target = Rig::new();

    let refused = target.builder.rebuild_verified(
        &entries,
        version(1),
        (LogEpoch::ZERO, PolicyDigestValue::ZERO),
    );

    assert!(matches!(
        refused,
        Err(SnapshotBuildError::DigestMismatch { .. })
    ));
    assert!(target.cell.current().is_none(), "nothing is published");
}

#[test]
fn a_host_whose_routes_do_not_compile_denies_alone_and_holds_nothing_back() {
    let mut rig = Rig::new();
    let other = RouteHost::new("other.example.com").unwrap();

    let outcome = rig.apply(vec![
        route_with_pattern(1, "api.example.com", "/same/{id}"),
        route_with_pattern(2, "api.example.com", "/same/{id}"),
        route_with_pattern(3, "other.example.com", "/fine/{id}"),
    ]);

    assert!(
        matches!(outcome, ApplyOutcome::Applied { .. }),
        "{outcome:?}"
    );
    assert_eq!(rig.snapshot().version(), version(1));
    let snapshot = rig.snapshot();
    assert!(
        snapshot
            .route(&host(), HttpMethod::Get, "/same/7")
            .is_none()
    );
    let found = snapshot.route(&other, HttpMethod::Get, "/fine/7").unwrap();
    assert_eq!(found.id, route_id(3));
}

#[test]
fn an_isolated_host_is_compiled_again_by_a_later_version() {
    let mut rig = Rig::new();
    rig.apply(vec![
        route_with_pattern(1, "api.example.com", "/same/{id}"),
        route_with_pattern(2, "api.example.com", "/same/{id}"),
    ]);
    assert!(
        rig.snapshot()
            .route(&host(), HttpMethod::Get, "/same/7")
            .is_none()
    );

    let outcome = rig.apply(vec![(route_key(2), None)]);
    rig.builder.flush();

    assert!(
        matches!(outcome, ApplyOutcome::Applied { .. }),
        "{outcome:?}"
    );
    assert_eq!(rig.snapshot().version(), version(2));
    let snapshot = rig.snapshot();
    let found = snapshot.route(&host(), HttpMethod::Get, "/same/7").unwrap();
    assert_eq!(found.id, route_id(1));
}

#[test]
fn routes_that_name_a_parameter_differently_share_a_host() {
    let mut rig = Rig::new();

    let outcome = rig.apply(vec![
        route_with_pattern(1, "api.example.com", "/a/{x}"),
        route_with_pattern(2, "api.example.com", "/a/{y}/b"),
    ]);

    assert!(
        matches!(outcome, ApplyOutcome::Applied { .. }),
        "{outcome:?}"
    );
    let snapshot = rig.snapshot();
    let first = snapshot.route(&host(), HttpMethod::Get, "/a/1").unwrap();
    let second = snapshot.route(&host(), HttpMethod::Get, "/a/1/b").unwrap();
    assert_eq!(first.id, route_id(1));
    assert_eq!(second.id, route_id(2));
}
