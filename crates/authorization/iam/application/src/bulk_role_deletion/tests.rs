use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AssignmentScope, BulkChunkCommitter as _, BulkChunker, BulkKind, BulkOperation,
    BulkOperationId, BulkStamp, BulkStatus, ChangeStatement, ChunkCommitError, EntityVersion,
    IamChange, PermissionGrantSet, PolicyEpochRepository, RoleId, RoleKind, RoleName, RoleParts,
    SubjectRef, UserRoleId, UserRoleParts,
};
use shared_domain::Uuid;
use test_support::bulk_operation::FakeBulkRoleTargetStore;
use test_support::id::SequenceUuidGenerator;
use test_support::policy_epoch::FakePolicyEpochRepository;
use test_support::role::FakeRoleRepository;
use test_support::unit_of_work::FakeIamUnitOfWork;
use test_support::user_role::FakeUserRoleRepository;

use super::{RoleDeletionChunkCommitter, RoleDeletionPorts};

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";
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

fn operation_id() -> BulkOperationId {
    BulkOperationId::parse(OPERATION).unwrap()
}

fn role_id() -> RoleId {
    RoleId::parse(ROLE).unwrap()
}

fn role() -> RoleParts {
    RoleParts {
        id: role_id(),
        name: RoleName::new("Billing".to_owned()).unwrap(),
        description: None,
        kind: RoleKind::Custom,
        grants: PermissionGrantSet::new(std::iter::empty()).unwrap(),
        version: EntityVersion::INITIAL,
        created_at: at(),
        updated_at: at(),
        deleted_at: None,
    }
}

fn assignment(number: u32) -> UserRoleParts {
    UserRoleParts {
        id: UserRoleId::parse(&format!("0190f2a8-7b3c-7d4e-8f20-{number:012x}")).unwrap(),
        subject: SubjectRef::user(
            Uuid::parse(&format!("0190f2a8-7b3c-7d4e-8f30-{number:012x}")).unwrap(),
        ),
        role_id: role_id(),
        scope: AssignmentScope::Global,
        expires_at: None,
        version: EntityVersion::new(2).unwrap(),
        created_by: actor(),
        created_at: SystemTime::UNIX_EPOCH,
        updated_at: SystemTime::UNIX_EPOCH,
        revoked_at: None,
    }
}

fn operation(total: u64) -> BulkOperation {
    BulkOperation::pending(operation_id(), BulkKind::RoleDeletion, total, actor(), at()).unwrap()
}

fn stamp() -> BulkStamp {
    BulkStamp {
        event_id: Uuid::parse(EVENT).unwrap(),
        occurred_at: at(),
    }
}

struct Doubles {
    roles: Vec<RoleParts>,
    assignments: u32,
    targets: FakeBulkRoleTargetStore,
    policy_epochs: FakePolicyEpochRepository,
    unit_of_work: Arc<FakeIamUnitOfWork>,
}

impl Doubles {
    fn standard(assignments: u32) -> Self {
        Self {
            roles: vec![role()],
            assignments,
            targets: FakeBulkRoleTargetStore::holding(operation_id(), role_id()),
            policy_epochs: FakePolicyEpochRepository::new(),
            unit_of_work: Arc::new(FakeIamUnitOfWork::new()),
        }
    }

    fn committer(
        self,
        chunk_entities: usize,
    ) -> (RoleDeletionChunkCommitter, Arc<FakeIamUnitOfWork>) {
        let unit_of_work = Arc::clone(&self.unit_of_work);
        let policy_epochs: Arc<dyn PolicyEpochRepository> = Arc::new(self.policy_epochs);
        let ports = RoleDeletionPorts {
            roles: Arc::new(FakeRoleRepository::holding(self.roles)),
            user_roles: Arc::new(FakeUserRoleRepository::holding(
                (1..=self.assignments).map(assignment).collect(),
            )),
            targets: Arc::new(self.targets),
            policy_epochs,
            unit_of_work: self.unit_of_work,
            ids: Arc::new(SequenceUuidGenerator::starting_at(1)),
        };
        let chunker = BulkChunker::new(chunk_entities).unwrap();
        (
            RoleDeletionChunkCommitter::new(ports, chunker),
            unit_of_work,
        )
    }
}

fn only(unit_of_work: &FakeIamUnitOfWork) -> IamChange {
    let mut committed = unit_of_work.committed();
    assert_eq!(committed.len(), 1);
    committed.remove(0)
}

fn revocations(change: &IamChange) -> usize {
    change
        .parts()
        .statements
        .iter()
        .filter(|statement| matches!(statement, ChangeStatement::SaveUserRole(_)))
        .count()
}

#[tokio::test]
async fn a_chunk_revokes_at_most_the_chunk_size_and_records_the_progress() {
    let (committer, unit_of_work) = Doubles::standard(3).committer(2);

    let chunk = committer
        .commit_next_chunk(&operation(4), stamp())
        .await
        .unwrap();

    assert_eq!(chunk.records, 2);
    assert_eq!(chunk.version.value(), 1);
    let change = only(&unit_of_work);
    assert_eq!(revocations(&change), 2);
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
async fn the_chunk_after_the_last_revocation_deletes_the_role_and_completes_the_operation() {
    let (committer, unit_of_work) = Doubles::standard(0).committer(1_000);

    let chunk = committer
        .commit_next_chunk(&operation(1), stamp())
        .await
        .unwrap();

    assert_eq!(chunk.records, 1);
    let change = only(&unit_of_work);
    assert_eq!(revocations(&change), 0);
    assert!(
        change
            .parts()
            .statements
            .iter()
            .any(|statement| matches!(statement, ChangeStatement::SaveRole(_)))
    );
    let types: Vec<&str> = change
        .parts()
        .events
        .iter()
        .map(|event| event.parts().event_type.as_str())
        .collect();
    assert!(types.contains(&"iam.role.deleted"), "{types:?}");
    assert!(types.contains(&"iam.bulk_operation.completed"), "{types:?}");
}

#[tokio::test]
async fn a_deletion_chunk_applies_the_records_that_other_changes_already_revoked() {
    let (committer, unit_of_work) = Doubles::standard(0).committer(1_000);

    let chunk = committer
        .commit_next_chunk(&operation(5), stamp())
        .await
        .unwrap();

    assert_eq!(chunk.records, 5);
    assert_eq!(only(&unit_of_work).parts().statements.len(), 3);
}

#[tokio::test]
async fn a_role_that_gained_assignments_fails_the_operation_without_a_commit() {
    let (committer, unit_of_work) = Doubles::standard(1).committer(1_000);

    let error = committer
        .commit_next_chunk(&operation(1), stamp())
        .await
        .unwrap_err();

    assert!(matches!(error, ChunkCommitError::Permanent(_)));
    assert_eq!(unit_of_work.committed(), Vec::<IamChange>::new());
}

#[tokio::test]
async fn an_operation_without_a_stored_target_fails_for_good() {
    let mut doubles = Doubles::standard(1);
    doubles.targets = FakeBulkRoleTargetStore::new();
    let (committer, unit_of_work) = doubles.committer(10);

    let error = committer
        .commit_next_chunk(&operation(2), stamp())
        .await
        .unwrap_err();

    assert!(matches!(error, ChunkCommitError::Permanent(_)));
    assert_eq!(unit_of_work.committed(), Vec::<IamChange>::new());
}

#[tokio::test]
async fn a_role_that_is_gone_fails_the_operation_for_good() {
    let mut doubles = Doubles::standard(1);
    doubles.roles = Vec::new();
    let (committer, _unit_of_work) = doubles.committer(10);

    let error = committer
        .commit_next_chunk(&operation(2), stamp())
        .await
        .unwrap_err();

    assert!(matches!(error, ChunkCommitError::Permanent(_)));
}

#[tokio::test]
async fn a_storage_failure_is_retried_later_and_commits_nothing() {
    let mut targets = Doubles::standard(1);
    targets.targets = FakeBulkRoleTargetStore::failing();
    let mut epochs = Doubles::standard(1);
    epochs.policy_epochs = FakePolicyEpochRepository::failing();
    let mut writes = Doubles::standard(1);
    writes.unit_of_work = Arc::new(FakeIamUnitOfWork::failing());

    for doubles in [targets, epochs, writes] {
        let (committer, unit_of_work) = doubles.committer(10);

        let error = committer
            .commit_next_chunk(&operation(2), stamp())
            .await
            .unwrap_err();

        assert!(matches!(error, ChunkCommitError::Unavailable(_)));
        assert_eq!(unit_of_work.committed(), Vec::<IamChange>::new());
    }
}

#[tokio::test]
async fn a_system_role_is_refused_for_good() {
    let mut doubles = Doubles::standard(0);
    doubles.roles = vec![RoleParts {
        kind: RoleKind::System,
        ..role()
    }];
    let (committer, unit_of_work) = doubles.committer(10);

    let error = committer
        .commit_next_chunk(&operation(1), stamp())
        .await
        .unwrap_err();

    assert!(matches!(error, ChunkCommitError::Permanent(_)));
    assert_eq!(unit_of_work.committed(), Vec::<IamChange>::new());
}

#[tokio::test]
async fn a_chunk_larger_than_one_page_reads_the_assignments_page_after_page() {
    let (committer, unit_of_work) = Doubles::standard(150).committer(120);

    let chunk = committer
        .commit_next_chunk(&operation(151), stamp())
        .await
        .unwrap();

    assert_eq!(chunk.records, 120);
    assert_eq!(revocations(&only(&unit_of_work)), 120);
}

#[tokio::test]
async fn a_policy_version_that_cannot_grow_is_a_permanent_failure_and_commits_nothing() {
    use iam_domain::{LogEpoch, PolicyDigestValue, PolicyEpoch, PolicyVersion, RelayEpoch};

    let last = PolicyEpoch::new(
        PolicyVersion::new(i64::MAX).unwrap(),
        PolicyDigestValue::ZERO,
        LogEpoch::new(0).unwrap(),
        RelayEpoch::new(0).unwrap(),
        0,
    )
    .unwrap();
    let doubles = Doubles {
        policy_epochs: FakePolicyEpochRepository::holding(last),
        ..Doubles::standard(1)
    };
    let (committer, unit_of_work) = doubles.committer(2);

    let error = committer
        .commit_next_chunk(&operation(2), stamp())
        .await
        .unwrap_err();

    assert!(matches!(error, ChunkCommitError::Permanent(_)));
    assert_eq!(unit_of_work.committed(), Vec::<IamChange>::new());
}
