//! Random histories: incremental apply, with duplicates, tombstones and relay takeovers, reaches
//! the same state as a full rebuild from the final raw state.

use iam_domain::{HttpMethod, LogEpoch, RouteHost, RouteId};
use rand::RngExt as _;
use test_support::seed::TestRng;

use super::support::{
    Edit, Rig, catalogue, manifest_key, rate_policy, rate_policy_id, role, role_key, route,
    route_key, service, subject, subject_ref, upstream, upstream_id, upstream_key, version,
};
use super::{RawEntry, shuffle};

const VERSIONS: usize = 40;
const CASES: usize = 12;
const GRANTS: [&str; 5] = [
    "rest:cat-0:GET /users",
    "rest:cat-0:POST /users",
    "gql:cat-0:Query.users",
    "rest:cat-0:*",
    "gql:cat-1:Query.*",
];
const HOSTS: [&str; 2] = ["api.example.com", "other.example.com"];

/// The live state of the rig as entries of a full rebuild.
pub(super) fn raw_entries(rig: &Rig) -> Vec<RawEntry> {
    rig.model
        .iter()
        .map(|(key, (changed_in, state))| RawEntry {
            key: key.clone(),
            version: *changed_in,
            payload: rig.encode(state),
        })
        .collect()
}

fn below(rng: &mut TestRng, bound: u32) -> u32 {
    between(rng, 0, bound)
}

fn between(rng: &mut TestRng, low: u32, high: u32) -> u32 {
    rng.rng().random_range(low..high)
}

fn role_edit(rng: &mut TestRng) -> Edit {
    let number = between(rng, 1, 5);
    if below(rng, 5) == 0 {
        return (role_key(number), None);
    }
    let grants: Vec<&str> = GRANTS
        .iter()
        .copied()
        .filter(|_grant| below(rng, 2) == 0)
        .collect();
    role(number, &grants)
}

fn subject_edit(rng: &mut TestRng) -> Edit {
    let roles: Vec<u32> = (1..=4).filter(|_role| below(rng, 3) == 0).collect();
    subject(between(rng, 1, 9), &roles)
}

fn upstream_edit(rng: &mut TestRng) -> Edit {
    let number = below(rng, 4);
    if below(rng, 5) == 0 {
        return (upstream_key(number), None);
    }
    upstream(number, i64::from(between(rng, 8_000, 8_100)))
}

fn route_edit(rng: &mut TestRng) -> Edit {
    let number = between(rng, 1, 6);
    if below(rng, 5) == 0 {
        return (route_key(number), None);
    }
    let host = HOSTS[usize::try_from(below(rng, 2)).unwrap()];
    route(number, host)
}

fn rate_policy_edit(rng: &mut TestRng) -> Edit {
    let number = between(rng, 1, 4);
    if below(rng, 5) == 0 {
        return (
            iam_domain::StateKey::RatePolicy(rate_policy_id(number)),
            None,
        );
    }
    rate_policy(number, i64::from(between(rng, 10, 100)))
}

fn catalogue_edits(rng: &mut TestRng) -> Vec<Edit> {
    let number = below(rng, 2);
    let chunk = ["aa", "bb"][usize::try_from(below(rng, 2)).unwrap()];
    let keys: Vec<&str> = GRANTS
        .iter()
        .copied()
        .filter(|_key| below(rng, 2) == 0)
        .collect();
    let (manifest, chunk_edit) = catalogue(number, chunk, &keys);
    match below(rng, 4) {
        0 => vec![manifest],
        1 => vec![chunk_edit],
        2 => vec![(manifest_key(number), None)],
        _ => vec![manifest, chunk_edit],
    }
}

fn random_edits(rng: &mut TestRng) -> Vec<Edit> {
    let mut edits = Vec::new();
    for _ in 0..=below(rng, 4) {
        match below(rng, 6) {
            0 => edits.push(role_edit(rng)),
            1 => edits.push(subject_edit(rng)),
            2 => edits.push(upstream_edit(rng)),
            3 => edits.push(route_edit(rng)),
            4 => edits.push(rate_policy_edit(rng)),
            _ => edits.extend(catalogue_edits(rng)),
        }
    }
    edits
}

/// Writes one version and offers its records shuffled, some of them twice; now and then the relay
/// is taken over, and an older version is sent again.
fn step(rig: &mut Rig, rng: &mut TestRng, history: &mut Vec<Vec<iam_domain::VersionedRecord>>) {
    if below(rng, 6) == 0 {
        rig.relay_epoch = rig.relay_epoch.checked_add(1).unwrap();
    }
    let records = rig.write(random_edits(rng));
    let mut offered = records.clone();
    offered.extend(records.iter().filter(|_| below(rng, 3) == 0).cloned());
    shuffle(&mut offered, rng);
    for record in offered {
        rig.builder.offer(record);
    }
    history.push(records);
    if below(rng, 4) == 0 {
        let index = usize::try_from(below(rng, u32::try_from(history.len()).unwrap())).unwrap();
        for record in history[index].clone() {
            rig.builder.offer(record);
        }
    }
    if below(rng, 3) == 0 {
        rig.builder.flush();
    }
}

fn probe(rig: &Rig) -> Probe {
    let snapshot = rig.cell.load().expect("a published snapshot");
    let reading = snapshot.as_ref();
    let hosts: Vec<RouteHost> = HOSTS
        .iter()
        .map(|host| RouteHost::new(host).unwrap())
        .collect();
    Probe {
        entries: reading.raw_entries(),
        roles: (1..=4)
            .map(|number| reading.working().role_set(role_id(number)).cloned())
            .collect(),
        assignments: (1..=8)
            .map(|number| reading.working().assignments(&subject_ref(number)).to_vec())
            .collect(),
        holders: (1..=4)
            .map(|number| reading.working().subjects_of_role(role_id(number)))
            .collect(),
        upstreams: (0..4)
            .map(|number| {
                reading
                    .working()
                    .upstream_by_id(upstream_id(number))
                    .cloned()
            })
            .collect(),
        routes: hosts
            .iter()
            .flat_map(|host| (1..=5).map(move |number| (host.clone(), number)))
            .map(|(host, number)| {
                reading
                    .working()
                    .route(&host, HttpMethod::Get, &format!("/r{number}/x"))
                    .map(|found| found.id)
            })
            .collect(),
        catalogues: (0..2)
            .map(|number| {
                reading
                    .working()
                    .catalogue(&service(number))
                    .map(<[_]>::to_vec)
            })
            .collect(),
        rate_policies: (1..=3)
            .map(|number| {
                reading
                    .working()
                    .rate_policy(rate_policy_id(number))
                    .cloned()
            })
            .collect(),
        version: reading.working().version,
        digest: reading.working().digest,
        derived_hash: reading.working().derived_hash,
    }
}

fn role_id(number: u32) -> iam_domain::RoleId {
    iam_domain::RoleId::from_uuid(super::support::uuid(number))
}

/// Everything a snapshot answers, to compare two of them.
#[derive(Debug, PartialEq)]
struct Probe {
    entries: Vec<(
        iam_domain::StateKey,
        iam_domain::PolicyVersion,
        iam_domain::PolicyState,
    )>,
    roles: Vec<Option<iam_domain::CompiledRoleSet>>,
    assignments: Vec<Vec<iam_domain::AssignmentState>>,
    holders: Vec<Vec<iam_domain::SubjectRef>>,
    upstreams: Vec<Option<iam_domain::UpstreamState>>,
    routes: Vec<Option<RouteId>>,
    catalogues: Vec<Option<Vec<iam_domain::CatalogueEntryState>>>,
    rate_policies: Vec<Option<iam_domain::RatePolicyState>>,
    version: iam_domain::PolicyVersion,
    digest: iam_domain::PolicyDigestValue,
    derived_hash: iam_domain::PolicyDigestValue,
}

#[test]
fn incremental_apply_equals_a_full_rebuild_of_the_final_raw_state() {
    let mut rng = TestRng::from_env();
    for _case in 0..CASES {
        let mut rig = Rig::new();
        let mut history = Vec::new();
        for _ in 0..VERSIONS {
            step(&mut rig, &mut rng, &mut history);
        }
        rig.builder.flush();
        let mut rebuilt = Rig::new();
        rebuilt
            .builder
            .rebuild(
                &raw_entries(&rig),
                version(rig.version),
                LogEpoch::new(1).unwrap(),
            )
            .unwrap();

        let incremental = probe(&rig);
        assert_eq!(incremental, probe(&rebuilt), "seed {}", rng.seed());
        assert_eq!(incremental.digest, rig.digest, "seed {}", rng.seed());
        assert_eq!(incremental.version, version(rig.version));
    }
}

#[test]
fn the_derived_hash_moves_with_the_derived_structures() {
    let mut rig = Rig::new();
    rig.apply(vec![role(1, &[GRANTS[0]]), subject(1, &[1])]);
    rig.builder.flush();
    let first = probe(&rig).derived_hash;

    rig.apply(vec![subject(1, &[])]);
    rig.builder.flush();
    let second = probe(&rig).derived_hash;
    rig.apply(vec![subject(1, &[1])]);
    rig.builder.flush();

    assert_ne!(first, second);
    assert_eq!(probe(&rig).derived_hash, first);
}
