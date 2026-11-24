use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AuditSummary, BulkChunkCommitter as _, BulkChunker, BulkKind, BulkOperation,
    BulkOperationId, BulkStamp, BulkStatus, ChangeStatement, ChunkCommitError, IamChange,
    InventoryEntry, RoleId, ServiceName, StateKey,
};
use shared_domain::Uuid;
use test_support::id::SequenceUuidGenerator;
use test_support::policy_epoch::FakePolicyEpochRepository;
use test_support::policy_state_inventory::FakePolicyStateInventory;
use test_support::unit_of_work::FakeIamUnitOfWork;

use super::{ResyncChunkCommitter, ResyncPorts};

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const OPERATION: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890af";
const EVENT: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890b0";

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn actor() -> ActorRef {
    ActorRef::User(Uuid::parse(USER).unwrap())
}

fn operation(total: u64, applied: u64) -> BulkOperation {
    let mut operation = BulkOperation::pending(
        BulkOperationId::parse(OPERATION).unwrap(),
        BulkKind::Resync,
        total,
        actor(),
        at(),
    )
    .unwrap();
    if applied > 0 {
        // The earlier chunks wrote the version the fake epoch repository holds (the seeded 0), so
        // the next chunk takes version 1 above it.
        let version = iam_domain::PolicyVersion::new(0).unwrap();
        operation.record_chunk(applied, version, stamp()).unwrap();
    }
    operation
}

fn stamp() -> BulkStamp {
    BulkStamp {
        event_id: Uuid::parse(EVENT).unwrap(),
        occurred_at: at(),
    }
}

fn role(number: u128) -> InventoryEntry {
    let id = RoleId::parse(&format!("0190f2a8-7b3c-7d4e-8f40-{number:012x}")).unwrap();
    InventoryEntry::State(StateKey::Role(id))
}

fn entries(count: u128) -> Vec<InventoryEntry> {
    (1..=count).map(role).collect()
}

fn committer(
    inventory: FakePolicyStateInventory,
    chunk_entities: usize,
) -> (ResyncChunkCommitter, Arc<FakeIamUnitOfWork>) {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let ports = ResyncPorts {
        policy_epochs: Arc::new(FakePolicyEpochRepository::new()),
        inventory: Arc::new(inventory),
        unit_of_work: Arc::<FakeIamUnitOfWork>::clone(&unit_of_work),
        ids: Arc::new(SequenceUuidGenerator::starting_at(1)),
    };
    (
        ResyncChunkCommitter::new(ports, BulkChunker::new(chunk_entities).unwrap()),
        unit_of_work,
    )
}

fn only(unit_of_work: &FakeIamUnitOfWork) -> IamChange {
    let mut committed = unit_of_work.committed();
    assert_eq!(committed.len(), 1);
    committed.remove(0)
}

fn republished(change: &IamChange) -> (Vec<StateKey>, Vec<ServiceName>) {
    let statement = change
        .parts()
        .statements
        .iter()
        .find_map(|statement| {
            if let ChangeStatement::RepublishState(republication) = statement {
                Some(republication)
            } else {
                None
            }
        })
        .unwrap();
    (statement.keys().to_vec(), statement.services().to_vec())
}

#[tokio::test]
async fn a_chunk_republishes_at_most_the_chunk_size_and_records_the_progress() {
    let (committer, unit_of_work) = committer(FakePolicyStateInventory::holding(entries(5)), 2);

    let chunk = committer
        .commit_next_chunk(&operation(5, 0), stamp())
        .await
        .unwrap();

    assert_eq!(chunk.records, 2);
    assert_eq!(chunk.version.value(), 1);
    let change = only(&unit_of_work);
    let (keys, services) = republished(&change);
    assert_eq!(
        keys,
        vec![
            StateKey::Role(RoleId::parse("0190f2a8-7b3c-7d4e-8f40-000000000001").unwrap()),
            StateKey::Role(RoleId::parse("0190f2a8-7b3c-7d4e-8f40-000000000002").unwrap()),
        ]
    );
    assert_eq!(services.len(), 0);
    let progress = change
        .parts()
        .statements
        .iter()
        .find_map(|statement| {
            if let ChangeStatement::SaveBulkProgress(progress) = statement {
                Some(progress)
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(progress.expected_applied(), 0);
    assert_eq!(progress.operation().applied_records, 2);
    assert_eq!(progress.operation().status, BulkStatus::Running);
    assert!(
        change
            .parts()
            .statements
            .iter()
            .any(|statement| matches!(statement, ChangeStatement::ExpectPolicyVersion(_)))
    );
}

#[tokio::test]
async fn the_next_chunk_continues_after_the_applied_records() {
    let (committer, unit_of_work) = committer(FakePolicyStateInventory::holding(entries(5)), 2);

    let chunk = committer
        .commit_next_chunk(&operation(5, 2), stamp())
        .await
        .unwrap();

    assert_eq!(chunk.records, 2);
    let (keys, _services) = republished(&only(&unit_of_work));
    assert_eq!(
        keys,
        vec![
            StateKey::Role(RoleId::parse("0190f2a8-7b3c-7d4e-8f40-000000000003").unwrap()),
            StateKey::Role(RoleId::parse("0190f2a8-7b3c-7d4e-8f40-000000000004").unwrap()),
        ]
    );
}

#[tokio::test]
async fn the_last_chunk_completes_the_operation_and_records_the_completion_event() {
    let (committer, unit_of_work) = committer(FakePolicyStateInventory::holding(entries(5)), 2);

    let chunk = committer
        .commit_next_chunk(&operation(5, 4), stamp())
        .await
        .unwrap();

    assert_eq!(chunk.records, 1);
    let change = only(&unit_of_work);
    let types: Vec<&str> = change
        .parts()
        .events
        .iter()
        .map(|event| event.parts().event_type.as_str())
        .collect();
    assert_eq!(types, ["iam.bulk_operation.completed"]);
    let progress = change
        .parts()
        .statements
        .iter()
        .find_map(|statement| {
            if let ChangeStatement::SaveBulkProgress(progress) = statement {
                Some(progress)
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(progress.operation().status, BulkStatus::Completed);
}

#[tokio::test]
async fn a_catalogue_entry_republishes_the_catalogue_of_its_service() {
    let service = ServiceName::new("billing").unwrap();
    let inventory = FakePolicyStateInventory::holding(vec![
        role(1),
        InventoryEntry::Catalogue(service.clone()),
    ]);
    let (committer, unit_of_work) = committer(inventory, 10);

    committer
        .commit_next_chunk(&operation(2, 0), stamp())
        .await
        .unwrap();

    let (keys, services) = republished(&only(&unit_of_work));
    assert_eq!(keys.len(), 1);
    assert_eq!(services, vec![service]);
}

#[tokio::test]
async fn a_policy_that_shrank_still_completes_the_operation_with_the_records_it_was_asked_for() {
    let (committer, unit_of_work) = committer(FakePolicyStateInventory::holding(entries(1)), 10);

    let chunk = committer
        .commit_next_chunk(&operation(4, 0), stamp())
        .await
        .unwrap();

    assert_eq!(chunk.records, 4);
    let (keys, _services) = republished(&only(&unit_of_work));
    assert_eq!(keys.len(), 1);
}

#[tokio::test]
async fn the_audit_record_names_the_operation_and_its_progress() {
    let (committer, unit_of_work) = committer(FakePolicyStateInventory::holding(entries(3)), 2);

    committer
        .commit_next_chunk(&operation(3, 0), stamp())
        .await
        .unwrap();

    let change = only(&unit_of_work);
    let audit = change.parts().audit.parts();
    assert_eq!(audit.action.as_str(), "bulk_operation.chunk");
    assert_eq!(audit.target.target_id(), OPERATION);
    assert_eq!(audit.actor, actor());
    assert_eq!(
        audit.before.as_ref().map(AuditSummary::as_str),
        Some("applied=0 total=3")
    );
    assert_eq!(
        audit.after.as_ref().map(AuditSummary::as_str),
        Some("applied=2 total=3 status=running")
    );
}

#[tokio::test]
async fn a_failing_dependency_is_unavailable_and_commits_nothing() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::failing());
    let failing_epochs = ResyncPorts {
        policy_epochs: Arc::new(FakePolicyEpochRepository::failing()),
        inventory: Arc::new(FakePolicyStateInventory::holding(entries(2))),
        unit_of_work: Arc::<FakeIamUnitOfWork>::clone(&unit_of_work),
        ids: Arc::new(SequenceUuidGenerator::starting_at(1)),
    };
    let failing_inventory = ResyncPorts {
        policy_epochs: Arc::new(FakePolicyEpochRepository::new()),
        inventory: Arc::new(FakePolicyStateInventory::failing()),
        unit_of_work: Arc::<FakeIamUnitOfWork>::clone(&unit_of_work),
        ids: Arc::new(SequenceUuidGenerator::starting_at(1)),
    };
    let failing_commit = ResyncPorts {
        policy_epochs: Arc::new(FakePolicyEpochRepository::new()),
        inventory: Arc::new(FakePolicyStateInventory::holding(entries(2))),
        unit_of_work: Arc::<FakeIamUnitOfWork>::clone(&unit_of_work),
        ids: Arc::new(SequenceUuidGenerator::starting_at(1)),
    };

    for ports in [failing_epochs, failing_inventory, failing_commit] {
        let committer = ResyncChunkCommitter::new(ports, BulkChunker::new(10).unwrap());

        let error = committer
            .commit_next_chunk(&operation(2, 0), stamp())
            .await
            .unwrap_err();

        assert!(matches!(error, ChunkCommitError::Unavailable(_)));
    }
}

#[tokio::test]
async fn a_finished_operation_cannot_take_another_chunk() {
    let (committer, unit_of_work) = committer(FakePolicyStateInventory::holding(entries(2)), 10);

    let error = committer
        .commit_next_chunk(&operation(2, 2), stamp())
        .await
        .unwrap_err();

    assert!(matches!(error, ChunkCommitError::Permanent(_)));
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[test]
fn a_locked_version_at_the_end_of_its_range_cannot_grow() {
    let locked = iam_domain::PolicyVersion::new(i64::MAX).unwrap();

    let error = super::next_version(locked).unwrap_err();

    assert!(matches!(error, ChunkCommitError::Permanent(_)));
}
