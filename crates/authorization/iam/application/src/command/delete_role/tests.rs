use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AssignmentExpiry, AssignmentScope, AuditOutcome, AuditSummary, BulkChunker, BulkKind,
    BulkOperationId, BulkOperationRepository as _, BulkRoleTargetStore as _, BulkStatus, ChangeId,
    ChangeStatement, DecisionEffect, EntityVersion, IamUnitOfWork, IdempotencyKey,
    IdempotencyRequest, PermissionGrantSet, PolicyVersion, RequestDigest, RoleId, RoleKind,
    RoleName, RoleParts, RoleRepository, SubjectRef, UserRoleId, UserRoleParts, UserRoleRepository,
};
use shared_domain::{Command as _, CommandHandler as _, Uuid};
use test_support::bulk_operation::{FakeBulkOperationRepository, FakeBulkRoleTargetStore};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::role::FakeRoleRepository;
use test_support::unit_of_work::FakeIamUnitOfWork;
use test_support::user_role::FakeUserRoleRepository;

use super::{
    BulkDeletionPath, DeleteRoleCommand, DeleteRoleCommandHandler, MAX_REVOKED_ASSIGNMENTS,
};
use crate::error::IamError;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const CHANGE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ac";
const ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";
const OTHER_ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ae";

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn actor() -> ActorRef {
    ActorRef::User(Uuid::parse(USER).unwrap())
}

fn version(value: i64) -> EntityVersion {
    EntityVersion::new(value).unwrap()
}

fn role(kind: RoleKind) -> RoleParts {
    RoleParts {
        id: RoleId::parse(ROLE).unwrap(),
        name: RoleName::new("Billing".to_owned()).unwrap(),
        description: None,
        kind,
        grants: PermissionGrantSet::new(std::iter::empty()).unwrap(),
        version: EntityVersion::INITIAL,
        created_at: at(),
        updated_at: at(),
        deleted_at: None,
    }
}

/// The assignment number `number` of the role `role_id` at version 2 that never expires.
fn assignment_of(role_id: &str, number: u32) -> UserRoleParts {
    UserRoleParts {
        id: UserRoleId::parse(&format!("0190f2a8-7b3c-7d4e-8f20-{number:012x}")).unwrap(),
        subject: SubjectRef::user(
            Uuid::parse(&format!("0190f2a8-7b3c-7d4e-8f30-{number:012x}")).unwrap(),
        ),
        role_id: RoleId::parse(role_id).unwrap(),
        scope: AssignmentScope::Global,
        expires_at: None,
        version: version(2),
        created_by: actor(),
        created_at: SystemTime::UNIX_EPOCH,
        updated_at: SystemTime::UNIX_EPOCH,
        revoked_at: None,
    }
}

fn assignments(count: u32) -> Vec<UserRoleParts> {
    (1..=count)
        .map(|number| assignment_of(ROLE, number))
        .collect()
}

fn command() -> DeleteRoleCommand {
    DeleteRoleCommand {
        change_id: ChangeId::parse(CHANGE).unwrap(),
        role_id: RoleId::parse(ROLE).unwrap(),
        actor: actor(),
        expected: EntityVersion::INITIAL,
        idempotency: None,
    }
}

fn handler(
    roles: FakeRoleRepository,
    user_roles: FakeUserRoleRepository,
    unit_of_work: &Arc<FakeIamUnitOfWork>,
) -> DeleteRoleCommandHandler {
    let roles: Arc<dyn RoleRepository> = Arc::new(roles);
    let user_roles: Arc<dyn UserRoleRepository> = Arc::new(user_roles);
    let unit_of_work: Arc<dyn IamUnitOfWork> = Arc::<FakeIamUnitOfWork>::clone(unit_of_work);
    DeleteRoleCommandHandler::new(
        roles,
        user_roles,
        unit_of_work,
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    )
}

fn standard(
    user_roles: Vec<UserRoleParts>,
    unit_of_work: &Arc<FakeIamUnitOfWork>,
) -> DeleteRoleCommandHandler {
    handler(
        FakeRoleRepository::holding(vec![role(RoleKind::Custom)]),
        FakeUserRoleRepository::holding(user_roles),
        unit_of_work,
    )
}

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(DeleteRoleCommand::NAME, "DeleteRoleCommand");
}

#[tokio::test]
async fn a_deletion_is_one_change_that_updates_the_role_and_every_assignment() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    standard(assignments(3), &unit_of_work)
        .handle(command())
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed.len(), 1);
    let parts = committed[0].parts();
    assert_eq!(parts.change_id, command().change_id);
    assert_eq!(parts.effect, DecisionEffect::Affected);
    assert_eq!(parts.entity_version, version(2));
    assert_eq!(unit_of_work.policy_version(), 1);
    assert_eq!(parts.statements.len(), 4);
    let ChangeStatement::SaveRole(statement) = &parts.statements[0] else {
        panic!("the role update comes first: {:?}", parts.statements);
    };
    assert_eq!(statement.expected(), Some(EntityVersion::INITIAL));
    assert_eq!(statement.role().version, version(2));
    assert_eq!(statement.role().deleted_at, Some(at()));
    assert_eq!(statement.actor(), &actor());
    for (index, statement) in parts.statements[1..].iter().enumerate() {
        let ChangeStatement::SaveUserRole(statement) = statement else {
            panic!("an assignment update expected: {statement:?}");
        };
        assert_eq!(statement.expected(), Some(version(2)));
        assert_eq!(statement.user_role().version, version(3));
        assert_eq!(statement.user_role().revoked_at, Some(at()));
        assert_eq!(statement.user_role().id, assignments(3)[index].id);
    }
}

#[tokio::test]
async fn the_receipt_reports_the_number_of_revoked_assignments() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    standard(assignments(3), &unit_of_work)
        .handle(command())
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed[0].revoked_assignments(), Some(3));
    let receipt = committed[0].receipt(PolicyVersion::new(1).unwrap());
    assert_eq!(receipt.revoked_assignments(), Some(3));
    assert_eq!(receipt.target().target_type(), "role");
    assert_eq!(receipt.target().target_id(), ROLE);
}

#[tokio::test]
async fn the_deletion_records_the_deleted_event_and_one_revoked_event_per_assignment() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    standard(assignments(3), &unit_of_work)
        .handle(command())
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let events = &committed[0].parts().events;
    let types: Vec<&str> = events
        .iter()
        .map(|event| event.parts().event_type.as_str())
        .collect();
    assert_eq!(
        types,
        [
            "iam.role.deleted",
            "iam.user_role.revoked",
            "iam.user_role.revoked",
            "iam.user_role.revoked"
        ]
    );
    assert_eq!(events[0].parts().aggregate_id, command().role_id.as_uuid());
    assert_eq!(events[0].parts().actor, actor());
    let deleted = format!("{:?}", events[0].parts().data);
    assert!(deleted.contains("revokedAssignments"), "{deleted}");
    assert!(deleted.contains("Billing"), "{deleted}");
    for (index, event) in events[1..].iter().enumerate() {
        assert_eq!(
            event.parts().aggregate_id,
            assignments(3)[index].id.as_uuid()
        );
        assert_eq!(event.parts().actor, actor());
        let data = format!("{:?}", event.parts().data);
        assert!(data.contains("role_deleted"), "{data}");
        assert!(data.contains("Billing"), "{data}");
    }
}

#[tokio::test]
async fn every_record_of_the_change_has_a_distinct_event_identifier() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    standard(assignments(3), &unit_of_work)
        .handle(command())
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let mut ids: Vec<_> = committed[0]
        .parts()
        .events
        .iter()
        .map(|event| format!("{:?}", event.parts().id))
        .collect();
    let total = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), total);
}

#[tokio::test]
async fn the_deletion_and_each_revocation_have_an_audit_record() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    standard(assignments(2), &unit_of_work)
        .handle(command())
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let audits = committed[0].audits(PolicyVersion::new(1).unwrap());
    assert_eq!(audits.len(), 3);
    let role_audit = audits[0].parts();
    assert_eq!(role_audit.action.as_str(), "role.delete");
    assert_eq!(role_audit.outcome, AuditOutcome::Committed);
    assert_eq!(role_audit.target.target_type(), "role");
    assert_eq!(role_audit.target.target_id(), ROLE);
    assert_eq!(
        role_audit.before.as_ref().map(AuditSummary::as_str),
        Some("kind=custom version=1")
    );
    assert_eq!(
        role_audit.after.as_ref().map(AuditSummary::as_str),
        Some("deleted version=2 revoked=2")
    );
    for (index, audit) in audits[1..].iter().enumerate() {
        let parts = audit.parts();
        let revoked = &assignments(2)[index];
        assert_eq!(parts.action.as_str(), "user_role.revoke");
        assert_eq!(parts.outcome, AuditOutcome::Committed);
        assert_eq!(parts.actor, actor());
        assert_eq!(parts.occurred_at, at());
        assert_eq!(parts.target.target_type(), "user_role");
        assert_eq!(parts.target.target_id(), revoked.id.to_string());
        assert_eq!(parts.scope, Some(AssignmentScope::Global));
        assert_eq!(parts.policy_version, PolicyVersion::new(1).ok());
        assert_eq!(
            parts.after.as_ref().map(AuditSummary::as_str),
            Some("revoked version=3 cause=role_deleted")
        );
    }
}

#[tokio::test]
async fn an_expired_assignment_is_revoked_with_the_others() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let expired = UserRoleParts {
        expires_at: Some(AssignmentExpiry::restore(
            at().checked_sub(Duration::from_hours(1)).unwrap(),
        )),
        ..assignment_of(ROLE, 2)
    };

    standard(vec![assignment_of(ROLE, 1), expired], &unit_of_work)
        .handle(command())
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed[0].revoked_assignments(), Some(2));
    assert_eq!(committed[0].parts().statements.len(), 3);
}

#[tokio::test]
async fn an_assignment_whose_version_cannot_grow_fails_the_deletion_before_any_commit() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let exhausted = UserRoleParts {
        version: version(i64::MAX),
        ..assignment_of(ROLE, 2)
    };

    let error = standard(vec![assignment_of(ROLE, 1), exhausted], &unit_of_work)
        .handle(command())
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Internal(_)), "{error:?}");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn assignments_of_other_roles_and_revoked_ones_are_left_alone() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let revoked = UserRoleParts {
        revoked_at: Some(SystemTime::UNIX_EPOCH),
        ..assignment_of(ROLE, 2)
    };

    standard(
        vec![
            assignment_of(ROLE, 1),
            revoked,
            assignment_of(OTHER_ROLE, 3),
        ],
        &unit_of_work,
    )
    .handle(command())
    .await
    .unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed[0].revoked_assignments(), Some(1));
    assert_eq!(committed[0].parts().statements.len(), 2);
}

#[tokio::test]
async fn a_role_without_assignments_is_deleted_with_a_count_of_zero() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    standard(Vec::new(), &unit_of_work)
        .handle(command())
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed[0].revoked_assignments(), Some(0));
    assert_eq!(committed[0].parts().statements.len(), 1);
    assert_eq!(committed[0].parts().events.len(), 1);
    assert_eq!(committed[0].audits(PolicyVersion::new(1).unwrap()).len(), 1);
}

#[tokio::test]
async fn every_page_of_assignments_is_revoked() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    standard(assignments(250), &unit_of_work)
        .handle(command())
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed[0].revoked_assignments(), Some(250));
    assert_eq!(committed[0].parts().statements.len(), 251);
}

#[tokio::test]
async fn exactly_one_full_page_ends_the_read_with_an_empty_page() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    standard(assignments(100), &unit_of_work)
        .handle(command())
        .await
        .unwrap();

    assert_eq!(unit_of_work.committed()[0].revoked_assignments(), Some(100));
}

#[tokio::test]
async fn the_largest_number_of_assignments_is_revoked_and_one_more_is_a_conflict() {
    let limit = u32::try_from(MAX_REVOKED_ASSIGNMENTS).unwrap();
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    standard(assignments(limit), &unit_of_work)
        .handle(command())
        .await
        .unwrap();
    let refused = standard(assignments(limit + 1), &Arc::new(FakeIamUnitOfWork::new()))
        .handle(command())
        .await
        .unwrap_err();

    assert_eq!(
        unit_of_work.committed()[0].revoked_assignments(),
        Some(limit)
    );
    assert!(matches!(refused, IamError::Conflict), "{refused:?}");
}

#[tokio::test]
async fn a_system_role_is_forbidden_before_any_commit() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    let error = handler(
        FakeRoleRepository::holding(vec![role(RoleKind::System)]),
        FakeUserRoleRepository::holding(assignments(1)),
        &unit_of_work,
    )
    .handle(command())
    .await
    .unwrap_err();

    assert!(matches!(error, IamError::Forbidden), "{error:?}");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn a_stale_version_is_a_failed_precondition_before_any_commit() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let stale = DeleteRoleCommand {
        expected: version(7),
        ..command()
    };

    let error = standard(assignments(2), &unit_of_work)
        .handle(stale)
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::PreconditionFailed), "{error:?}");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn an_unknown_or_deleted_role_is_not_found() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let deleted = RoleParts {
        deleted_at: Some(at()),
        ..role(RoleKind::Custom)
    };

    for roles in [
        FakeRoleRepository::new(),
        FakeRoleRepository::holding(vec![deleted]),
    ] {
        let error = handler(roles, FakeUserRoleRepository::new(), &unit_of_work)
            .handle(command())
            .await
            .unwrap_err();

        assert!(matches!(error, IamError::NotFound), "{error:?}");
    }
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn unreadable_storage_is_a_storage_failure() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    let unreadable_role = handler(
        FakeRoleRepository::failing(),
        FakeUserRoleRepository::new(),
        &unit_of_work,
    )
    .handle(command())
    .await
    .unwrap_err();
    let unreadable_assignments = handler(
        FakeRoleRepository::holding(vec![role(RoleKind::Custom)]),
        FakeUserRoleRepository::failing(),
        &unit_of_work,
    )
    .handle(command())
    .await
    .unwrap_err();

    assert!(
        matches!(unreadable_role, IamError::Storage(_)),
        "{unreadable_role:?}"
    );
    assert!(
        matches!(unreadable_assignments, IamError::Storage(_)),
        "{unreadable_assignments:?}"
    );
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn the_idempotency_key_and_digest_travel_with_the_change() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let request = IdempotencyRequest {
        key: IdempotencyKey::new("delete-billing").unwrap(),
        request_digest: RequestDigest::new(&[7_u8; 32]).unwrap(),
    };
    let delete = DeleteRoleCommand {
        idempotency: Some(request.clone()),
        ..command()
    };

    standard(assignments(1), &unit_of_work)
        .handle(delete)
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed[0].parts().idempotency, Some(request.clone()));
    assert_eq!(
        committed[0].parts().audit.parts().idempotency_key,
        Some(request.key)
    );
    let audits = committed[0].audits(PolicyVersion::new(1).unwrap());
    assert_eq!(audits[1].parts().idempotency_key, None);
}

#[tokio::test]
async fn a_failing_unit_of_work_is_a_storage_failure() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::failing());

    let error = standard(assignments(1), &unit_of_work)
        .handle(command())
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)), "{error:?}");
}

struct Bulk {
    operations: Arc<FakeBulkOperationRepository>,
    targets: Arc<FakeBulkRoleTargetStore>,
    unit_of_work: Arc<FakeIamUnitOfWork>,
}

fn with_bulk(role: RoleParts, user_roles: Vec<UserRoleParts>) -> (DeleteRoleCommandHandler, Bulk) {
    let bulk = Bulk {
        operations: Arc::new(FakeBulkOperationRepository::new()),
        targets: Arc::new(FakeBulkRoleTargetStore::new()),
        unit_of_work: Arc::new(FakeIamUnitOfWork::new()),
    };
    let handler = handler(
        FakeRoleRepository::holding(vec![role]),
        FakeUserRoleRepository::holding(user_roles),
        &bulk.unit_of_work,
    )
    .with_bulk(BulkDeletionPath {
        operations: Arc::<FakeBulkOperationRepository>::clone(&bulk.operations),
        targets: Arc::<FakeBulkRoleTargetStore>::clone(&bulk.targets),
        chunker: BulkChunker::new(1_000).unwrap(),
    });
    (handler, bulk)
}

#[tokio::test]
async fn a_role_with_more_assignments_than_a_chunk_is_recorded_as_a_pending_bulk_operation() {
    let (handler, bulk) = with_bulk(role(RoleKind::Custom), assignments(2_500));

    handler.handle(command()).await.unwrap();

    assert_eq!(
        bulk.unit_of_work.committed(),
        Vec::<iam_domain::IamChange>::new()
    );
    let id = BulkOperationId::from_uuid(command().change_id.as_uuid());
    let stored = bulk.operations.find(id).await.unwrap().unwrap();
    let parts = stored.parts();
    assert_eq!(parts.kind, BulkKind::RoleDeletion);
    assert_eq!(parts.status, BulkStatus::Pending);
    assert_eq!(parts.total_records, 2_501);
    assert_eq!(parts.applied_records, 0);
    assert_eq!(parts.requester, actor());
    assert_eq!(
        bulk.targets.find(id).await.unwrap(),
        Some(command().role_id)
    );
}

#[tokio::test]
async fn a_role_whose_deletion_fits_one_chunk_is_deleted_in_one_change() {
    let (handler, bulk) = with_bulk(role(RoleKind::Custom), assignments(999));

    handler.handle(command()).await.unwrap();

    assert_eq!(bulk.unit_of_work.committed().len(), 1);
    assert_eq!(
        bulk.operations.snapshot(),
        Vec::<iam_domain::BulkOperationParts>::new()
    );
}

#[tokio::test]
async fn a_role_with_a_thousand_assignments_changes_more_entities_than_a_chunk() {
    let (handler, bulk) = with_bulk(role(RoleKind::Custom), assignments(1_000));

    handler.handle(command()).await.unwrap();

    assert_eq!(
        bulk.unit_of_work.committed(),
        Vec::<iam_domain::IamChange>::new()
    );
    assert_eq!(bulk.operations.snapshot()[0].total_records, 1_001);
}

#[tokio::test]
async fn a_system_role_or_a_stale_version_is_refused_before_any_operation_is_recorded() {
    let (handler, bulk) = with_bulk(role(RoleKind::System), assignments(2_500));
    let forbidden = handler.handle(command()).await.unwrap_err();
    let (handler, stale_bulk) = with_bulk(role(RoleKind::Custom), assignments(2_500));
    let stale = handler
        .handle(DeleteRoleCommand {
            expected: version(7),
            ..command()
        })
        .await
        .unwrap_err();

    assert!(matches!(forbidden, IamError::Forbidden), "{forbidden:?}");
    assert!(matches!(stale, IamError::PreconditionFailed), "{stale:?}");
    assert_eq!(
        bulk.operations.snapshot(),
        Vec::<iam_domain::BulkOperationParts>::new()
    );
    assert_eq!(
        stale_bulk.operations.snapshot(),
        Vec::<iam_domain::BulkOperationParts>::new()
    );
}
