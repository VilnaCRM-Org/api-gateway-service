use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    AssignmentScope, AssignmentState, CatalogueEntryState, CompiledRoleSet, GrantStatus,
    PermissionGrant, PolicyReadRepository as _, PolicySnapshot, PolicyVersion, RoleId, ServiceName,
    SubjectRef,
};
use shared_domain::Uuid;
use test_support::gateway_snapshot::GatewaySnapshot;

use super::{CatalogueCache, LoadedSnapshotReads};

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890cd";
const GONE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ce";

fn service() -> ServiceName {
    ServiceName::new("users").unwrap()
}

/// The entry of a key with its `[sensitive, audit_always]` flags.
fn entry(key: &str, [sensitive, audit_always]: [bool; 2]) -> CatalogueEntryState {
    CatalogueEntryState {
        key: key.to_owned(),
        sensitive,
        audit_always,
    }
}

fn reads(snapshot: GatewaySnapshot, cache: &Arc<CatalogueCache>) -> LoadedSnapshotReads {
    let snapshot: Arc<dyn PolicySnapshot> = Arc::new(snapshot);
    LoadedSnapshotReads::new(snapshot, Arc::clone(cache))
}

fn at(version: i64) -> GatewaySnapshot {
    GatewaySnapshot::at(PolicyVersion::new(version).unwrap())
}

fn operations(catalog: &iam_domain::ServiceCatalog) -> Vec<String> {
    let mut operations: Vec<String> = catalog
        .rest_operations()
        .iter()
        .flat_map(|set| set.iter().map(|(key, _)| key.to_string()))
        .collect();
    operations.sort();
    operations
}

#[tokio::test]
async fn a_subject_policy_holds_the_assignments_and_the_known_role_sets_of_the_snapshot() {
    let role = RoleId::parse(ROLE).unwrap();
    let gone = RoleId::parse(GONE).unwrap();
    let subject = SubjectRef::user(Uuid::parse(USER).unwrap());
    let set = CompiledRoleSet::compile([(
        PermissionGrant::parse("rest:users:GET /api/users").unwrap(),
        GrantStatus::Active,
    )]);
    let snapshot = at(5)
        .with_assignments(
            subject.clone(),
            vec![
                AssignmentState {
                    role,
                    scope: AssignmentScope::Global,
                    expires_at_micros: Some(2_000_000),
                },
                AssignmentState {
                    role: gone,
                    scope: AssignmentScope::Global,
                    expires_at_micros: None,
                },
            ],
        )
        .with_role_set(role, set.clone());

    let policy = reads(snapshot, &Arc::default())
        .read_subject_policy(&subject)
        .await
        .unwrap();

    assert_eq!(policy.policy_version(), PolicyVersion::new(5).unwrap());
    assert_eq!(policy.assignments().len(), 2);
    assert_eq!(
        policy
            .assignments()
            .first()
            .and_then(iam_domain::RoleAssignment::expires_at),
        SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(2))
    );
    assert_eq!(policy.assignments().get(1).unwrap().expires_at(), None);
    assert_eq!(policy.role_sets().len(), 1);
    assert_eq!(policy.role_sets().get(&role), Some(&set));
}

#[tokio::test]
async fn an_expiry_before_1970_reads_as_expired() {
    let role = RoleId::parse(ROLE).unwrap();
    let subject = SubjectRef::user(Uuid::parse(USER).unwrap());
    let snapshot = at(1).with_assignments(
        subject.clone(),
        vec![AssignmentState {
            role,
            scope: AssignmentScope::Global,
            expires_at_micros: Some(-1),
        }],
    );

    let policy = reads(snapshot, &Arc::default())
        .read_subject_policy(&subject)
        .await
        .unwrap();

    let held = policy.assignments().first().unwrap();
    assert!(
        !held.is_active_at(
            SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(1))
                .unwrap()
        )
    );
}

#[tokio::test]
async fn a_subject_without_assignments_has_an_empty_policy() {
    let subject = SubjectRef::user(Uuid::parse(USER).unwrap());

    let policy = reads(at(1), &Arc::default())
        .read_subject_policy(&subject)
        .await
        .unwrap();

    assert_eq!(policy.assignments().len(), 0);
    assert!(policy.role_sets().is_empty());
}

#[tokio::test]
async fn a_catalogue_holds_the_rest_operations_of_the_entries_with_their_flags() {
    let snapshot = at(3).with_catalogue(
        service(),
        vec![
            entry("rest:users:GET /api/users/{}", [false, false]),
            entry("rest:users:POST /api/users", [true, true]),
            entry("rest:users:DELETE /api/users/{}", [true, false]),
            entry("rest:users:PUT /api/users/{}", [false, true]),
            entry("gql:users:Query.users", [false, false]),
            entry("rest:orders:GET /api/orders", [false, false]),
            entry("rest:users:GET /api/{id}", [false, false]),
            entry("not a key", [false, false]),
        ],
    );

    let catalog = reads(snapshot, &Arc::default())
        .read_service_catalog(&service())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(catalog.policy_version(), PolicyVersion::new(3).unwrap());
    assert_eq!(
        operations(&catalog),
        [
            "DELETE /api/users/{}",
            "GET /api/users/{}",
            "POST /api/users",
            "PUT /api/users/{}",
        ]
    );
    assert_eq!(catalog.type_graphs().len(), 0);
    let mut flags: Vec<(String, bool, bool)> = catalog
        .rest_operations()
        .iter()
        .flat_map(|set| {
            set.iter().map(|(key, details)| {
                (
                    key.to_string(),
                    details.flags.is_sensitive(),
                    details.flags.is_audit_always(),
                )
            })
        })
        .collect();
    flags.sort();
    assert_eq!(
        flags,
        [
            ("DELETE /api/users/{}".to_owned(), true, false),
            ("GET /api/users/{}".to_owned(), false, false),
            ("POST /api/users".to_owned(), true, true),
            ("PUT /api/users/{}".to_owned(), false, true),
        ]
    );
}

#[tokio::test]
async fn a_duplicate_entry_is_not_kept_twice() {
    let snapshot = at(1).with_catalogue(
        service(),
        vec![
            entry("rest:users:GET /api/users", [false, false]),
            entry("rest:users:GET /api/users", [true, false]),
        ],
    );

    let catalog = reads(snapshot, &Arc::default())
        .read_service_catalog(&service())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(operations(&catalog), ["GET /api/users"]);
}

#[tokio::test]
async fn a_service_without_a_catalogue_has_none() {
    let found = reads(at(1), &Arc::default())
        .read_service_catalog(&service())
        .await
        .unwrap();

    assert!(found.is_none());
}

#[tokio::test]
async fn a_catalogue_is_derived_once_per_snapshot_version_and_again_for_the_next_one() {
    let cache = Arc::new(CatalogueCache::new());
    let first = at(1).with_catalogue(service(), vec![entry("rest:users:GET /a", [false, false])]);
    let same_version =
        at(1).with_catalogue(service(), vec![entry("rest:users:GET /b", [false, false])]);
    let next_version =
        at(2).with_catalogue(service(), vec![entry("rest:users:GET /b", [false, false])]);

    let derived = reads(first, &cache).read_service_catalog(&service()).await;
    let kept = reads(same_version, &cache)
        .read_service_catalog(&service())
        .await;
    let rederived = reads(next_version, &cache)
        .read_service_catalog(&service())
        .await;

    assert_eq!(operations(&derived.unwrap().unwrap()), ["GET /a"]);
    assert_eq!(operations(&kept.unwrap().unwrap()), ["GET /a"]);
    assert_eq!(operations(&rederived.unwrap().unwrap()), ["GET /b"]);
}
