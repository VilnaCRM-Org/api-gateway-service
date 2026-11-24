use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{
    AssignmentScope, AssignmentState, BootClock as _, BootInstant, CatalogueEntryState,
    CompiledRoleSet, FreshnessRule, GraphQlCoordinate, PolicyReadRepository as _, PolicyVersion,
    PolicyView as _, RepositoryError, RoleId, ServiceName, SubjectRef,
};
use shared_domain::Uuid;
use test_support::boot_clock::FakeBootClock;
use test_support::decision_snapshot::DecisionSnapshot;
use test_support::policy_view::FakePolicyView;

use super::{FreshPolicyView, SnapshotPolicyReads};
use crate::freshness::FreshnessState;

const HARD: Duration = Duration::from_secs(15);

fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

fn user() -> SubjectRef {
    SubjectRef::user(Uuid::parse("00000000-0000-0000-0000-0000000000a1").unwrap())
}

fn role() -> RoleId {
    RoleId::from_uuid(Uuid::parse("00000000-0000-0000-0000-0000000000b1").unwrap())
}

fn service(name: &str) -> ServiceName {
    ServiceName::new(name).unwrap()
}

/// The entry of a key with its `[sensitive, audit_always]` flags.
fn entry(key: &str, [sensitive, audit_always]: [bool; 2]) -> CatalogueEntryState {
    CatalogueEntryState {
        key: key.to_owned(),
        sensitive,
        audit_always,
    }
}

fn fresh_state() -> (Arc<FreshnessState>, Arc<FakeBootClock>) {
    let clock = Arc::new(FakeBootClock::starting_at(BootInstant::from_elapsed(
        Duration::from_secs(100),
    )));
    let state = FreshnessState::new(
        FreshnessRule::new(HARD, Duration::from_secs(2)),
        Arc::<FakeBootClock>::clone(&clock),
    );
    state.attach(
        FreshnessProof {
            taken_at: clock.now(),
            watermark: 1,
        },
        version(3),
    );
    (Arc::new(state), clock)
}

fn reads_of(snapshot: DecisionSnapshot) -> (SnapshotPolicyReads, Arc<FakeBootClock>) {
    let (state, clock) = fresh_state();
    let view = FakePolicyView::with_snapshot(Arc::new(snapshot));
    (SnapshotPolicyReads::new(Arc::new(view), state), clock)
}

fn assignment(expires_at_micros: Option<i64>) -> AssignmentState {
    AssignmentState {
        role: role(),
        scope: AssignmentScope::Global,
        expires_at_micros,
    }
}

#[tokio::test]
async fn a_subject_policy_holds_the_assignments_and_role_sets_of_the_snapshot_version() {
    let snapshot = DecisionSnapshot::at(version(3))
        .with_assignments(user(), vec![assignment(Some(2_000_000))])
        .with_role_set(role(), CompiledRoleSet::default());
    let (reads, _clock) = reads_of(snapshot);

    let policy = reads.read_subject_policy(&user()).await.unwrap();

    assert_eq!(policy.policy_version(), version(3));
    assert_eq!(policy.assignments().len(), 1);
    assert_eq!(
        policy.assignments()[0].expires_at(),
        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(2))
    );
    assert!(policy.role_sets().contains_key(&role()));
}

#[tokio::test]
async fn a_subject_without_assignments_has_an_empty_policy_at_the_snapshot_version() {
    let (reads, _clock) = reads_of(DecisionSnapshot::at(version(3)));

    let policy = reads.read_subject_policy(&user()).await.unwrap();

    assert_eq!(policy.policy_version(), version(3));
    assert_eq!(policy.assignments().len(), 0);
    assert!(policy.role_sets().is_empty());
}

#[tokio::test]
async fn an_assignment_that_expires_before_1970_cannot_be_read() {
    let snapshot =
        DecisionSnapshot::at(version(3)).with_assignments(user(), vec![assignment(Some(-1))]);
    let (reads, _clock) = reads_of(snapshot);

    let error = reads.read_subject_policy(&user()).await.unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}

#[tokio::test]
async fn nothing_is_read_before_a_snapshot_is_published() {
    let (state, _clock) = fresh_state();
    let reads = SnapshotPolicyReads::new(Arc::new(FakePolicyView::failing()), state);

    assert!(matches!(
        reads.read_subject_policy(&user()).await,
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        reads.read_service_catalog(&service("crm")).await,
        Err(RepositoryError::Unavailable(_))
    ));
}

#[tokio::test]
async fn nothing_is_read_once_the_proof_is_older_than_the_hard_bound() {
    let (reads, clock) = reads_of(DecisionSnapshot::at(version(3)));
    clock.advance(HARD + Duration::from_millis(1));

    assert!(matches!(
        reads.read_subject_policy(&user()).await,
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        reads.read_service_catalog(&service("crm")).await,
        Err(RepositoryError::Unavailable(_))
    ));
}

#[tokio::test]
async fn a_service_without_a_catalogue_has_no_active_version() {
    let (reads, _clock) = reads_of(DecisionSnapshot::at(version(3)));

    assert_eq!(
        reads.read_service_catalog(&service("crm")).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn the_catalogue_holds_the_rest_operations_and_graphql_coordinates_of_the_entries() {
    let entries = vec![
        entry("rest:crm:GET /api/contacts/{}", [false, false]),
        entry("rest:crm:DELETE /api/contacts/{}", [true, true]),
        entry("gql:crm:Query.contacts", [false, true]),
        entry("gql:crm:__introspection", [false, false]),
    ];
    let snapshot = DecisionSnapshot::at(version(3)).with_catalogue(service("crm"), entries);
    let (reads, _clock) = reads_of(snapshot);

    let catalog = reads
        .read_service_catalog(&service("crm"))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(catalog.policy_version(), version(3));
    assert_eq!(
        catalog
            .rest_operations()
            .iter()
            .map(iam_domain::RestOperationSet::len)
            .sum::<usize>(),
        2
    );
    let graph = &catalog.type_graphs()[0];
    let coordinate = GraphQlCoordinate::parse("Query.contacts").unwrap();
    assert!(graph.field(&coordinate).unwrap().flags.is_audit_always());
}

#[tokio::test]
async fn a_catalogue_without_graphql_entries_has_no_type_graph() {
    let entries = vec![entry("rest:crm:GET /api/contacts", [false, false])];
    let snapshot = DecisionSnapshot::at(version(3)).with_catalogue(service("crm"), entries);
    let (reads, _clock) = reads_of(snapshot);

    let catalog = reads
        .read_service_catalog(&service("crm"))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(catalog.type_graphs().len(), 0);
}

#[tokio::test]
async fn an_entry_that_is_no_key_of_the_service_cannot_be_read() {
    for key in [
        "not-a-key",
        "rest:other:GET /api/contacts",
        "rest:crm:GET /a/{x}",
    ] {
        let snapshot = DecisionSnapshot::at(version(3))
            .with_catalogue(service("crm"), vec![entry(key, [false, false])]);
        let (reads, _clock) = reads_of(snapshot);

        let outcome = reads.read_service_catalog(&service("crm")).await;

        assert!(
            matches!(outcome, Err(RepositoryError::Unavailable(_))),
            "{key}"
        );
    }
}

#[test]
fn serving_names_the_reason_a_snapshot_cannot_serve() {
    let (state, clock) = fresh_state();
    let missing = SnapshotPolicyReads::new(Arc::new(FakePolicyView::failing()), Arc::clone(&state));
    assert_eq!(
        missing.serving().unwrap_err().to_string(),
        "no policy snapshot is published yet"
    );

    let view = FakePolicyView::with_snapshot(Arc::new(DecisionSnapshot::at(version(3))));
    let reads = SnapshotPolicyReads::new(Arc::new(view), state);
    assert_eq!(reads.serving().unwrap().version(), version(3));
    clock.advance(HARD + Duration::from_millis(1));
    assert_eq!(
        reads.serving().unwrap_err().to_string(),
        "the policy snapshot is not proven fresh"
    );
}

#[test]
fn the_fresh_view_hands_out_the_snapshot_only_while_the_pod_is_fresh() {
    let (state, clock) = fresh_state();
    let view = FakePolicyView::with_snapshot(Arc::new(DecisionSnapshot::at(version(3))));
    let fresh = FreshPolicyView::new(Arc::new(view), state);

    assert_eq!(fresh.current().unwrap().version(), version(3));
    clock.advance(HARD + Duration::from_millis(1));
    assert!(fresh.current().is_none());
}

#[test]
fn the_fresh_view_has_nothing_before_a_snapshot_is_published() {
    let (state, _clock) = fresh_state();

    assert!(
        FreshPolicyView::new(Arc::new(FakePolicyView::failing()), state)
            .current()
            .is_none()
    );
}
