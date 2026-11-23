use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AuditChainHead, AuditHash, ChangeReceipt, ChangeStatement, DecisionEffect,
    EntityVersion, ExpiredOrphanedGrant, IamChange, IamChangeParts, IamUnitOfWork,
    MAX_PURGED_GRANTS_PER_RUN, PermissionGrant, PermissionGrantSet, PolicyVersion, PurgedRecords,
    RepositoryError, RetentionCutoffs, RoleId, RoleKind, RoleName, RoleParts, SystemComponent,
};
use shared_domain::{Command as _, CommandHandler as _};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::maintenance_store::{Failing, FakeMaintenanceStore};
use test_support::role::FakeRoleRepository;
use test_support::unit_of_work::FakeIamUnitOfWork;

use super::{RunMaintenanceCommand, RunMaintenanceCommandHandler};
use crate::error::IamError;

const ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";
const OTHER_ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ae";
const ORPHANED: &str = "rest:billing:GET /invoices";
const OTHER_ORPHANED: &str = "gql:billing:Query.invoices";
const KEPT: &str = "rest:billing:GET /customers";
const WILDCARD: &str = "gql:billing:*";
const RETENTION: Duration = Duration::from_hours(2_160);

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn grant(text: &str) -> PermissionGrant {
    PermissionGrant::parse(text).unwrap()
}

fn role(id: &str, grants: &[&str]) -> RoleParts {
    RoleParts {
        id: RoleId::parse(id).unwrap(),
        name: RoleName::new("Billing".to_owned()).unwrap(),
        description: None,
        kind: RoleKind::Custom,
        grants: PermissionGrantSet::new(grants.iter().map(|text| grant(text))).unwrap(),
        version: EntityVersion::INITIAL,
        created_at: at(),
        updated_at: at(),
        deleted_at: None,
    }
}

fn orphan(role_id: &str, text: &str, orphaned_hours_before_now: u64) -> ExpiredOrphanedGrant {
    ExpiredOrphanedGrant {
        role_id: RoleId::parse(role_id).unwrap(),
        grant: grant(text),
        orphaned_at: at()
            .checked_sub(Duration::from_hours(orphaned_hours_before_now))
            .unwrap(),
    }
}

fn command() -> RunMaintenanceCommand {
    RunMaintenanceCommand {
        orphaned_grant_retention: RETENTION,
    }
}

fn handler(
    store: &Arc<FakeMaintenanceStore>,
    roles: Vec<RoleParts>,
    unit_of_work: Arc<dyn IamUnitOfWork>,
) -> RunMaintenanceCommandHandler {
    RunMaintenanceCommandHandler::new(
        Arc::<FakeMaintenanceStore>::clone(store),
        Arc::new(FakeRoleRepository::holding(roles)),
        unit_of_work,
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    )
}

/// A unit of work that refuses every change as a conflict, as a role that changed meanwhile does.
#[derive(Debug)]
struct ConflictingUnitOfWork;

#[async_trait::async_trait]
impl IamUnitOfWork for ConflictingUnitOfWork {
    async fn commit(&self, _change: IamChange) -> Result<ChangeReceipt, RepositoryError> {
        Err(RepositoryError::Conflict)
    }
}

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(RunMaintenanceCommand::NAME, "RunMaintenanceCommand");
}

#[tokio::test]
async fn a_pass_asks_for_the_grants_orphaned_before_the_retention_and_for_the_records_before_theirs()
 {
    let store = Arc::new(FakeMaintenanceStore::new());
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(&store, Vec::new(), unit_of_work)
        .handle(command())
        .await
        .unwrap();

    let cutoffs = RetentionCutoffs::at(at(), RETENTION);
    assert_eq!(
        store.orphan_requests(),
        [(cutoffs.orphaned_grants, MAX_PURGED_GRANTS_PER_RUN)]
    );
    assert_eq!(store.cutoffs(), [cutoffs]);
    assert_eq!(
        cutoffs.orphaned_grants,
        at().checked_sub(RETENTION).unwrap()
    );
}

/// Checks the role statement of a purge that removed `ORPHANED` from a role that held `KEPT` and
/// the wildcard as well.
fn assert_role_statement(parts: &IamChangeParts) {
    let [ChangeStatement::SaveRole(statement)] = parts.statements.as_slice() else {
        panic!("one role statement expected: {:?}", parts.statements);
    };
    assert_eq!(statement.expected(), Some(EntityVersion::INITIAL));
    assert_eq!(statement.role().version, EntityVersion::new(2).unwrap());
    assert!(!statement.role().grants.contains(&grant(ORPHANED)));
    assert!(statement.role().grants.contains(&grant(KEPT)));
    assert!(statement.role().grants.contains(&grant(WILDCARD)));
    assert_eq!(
        statement.actor(),
        &ActorRef::System(SystemComponent::Maintenance)
    );
}

#[tokio::test]
async fn a_purged_grant_leaves_its_role_in_one_change_with_an_event_and_an_audit_record() {
    let store =
        Arc::new(FakeMaintenanceStore::new().with_orphans(vec![orphan(ROLE, ORPHANED, 2_161)]));
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let roles = vec![role(ROLE, &[ORPHANED, KEPT, WILDCARD])];

    handler(
        &store,
        roles,
        Arc::<FakeIamUnitOfWork>::clone(&unit_of_work),
    )
    .handle(command())
    .await
    .unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed.len(), 1);
    let parts = committed[0].parts();
    assert_eq!(parts.effect, DecisionEffect::Affected);
    assert_eq!(parts.entity_version, EntityVersion::new(2).unwrap());
    assert_eq!(unit_of_work.policy_version(), 1);
    assert_role_statement(parts);
    let types: Vec<&str> = parts
        .events
        .iter()
        .map(|event| event.parts().event_type.as_str())
        .collect();
    assert_eq!(types, ["iam.role_permissions.changed"]);
    let data = format!("{:?}", parts.events[0].parts().data);
    assert!(data.contains(ORPHANED), "{data}");
    let audit = parts.audit.parts();
    assert_eq!(audit.action.as_str(), "role.orphaned_grant.purged");
    assert_eq!(audit.target.target_type(), "role");
    assert_eq!(audit.target.target_id(), ROLE);
    assert_eq!(audit.actor, ActorRef::System(SystemComponent::Maintenance));
    let before = audit.before.as_ref().unwrap();
    assert!(before.as_str().contains(ORPHANED), "{}", before.as_str());
}

#[tokio::test]
async fn every_purged_grant_of_a_role_gets_its_own_audit_record_in_the_same_change() {
    let store = Arc::new(FakeMaintenanceStore::new().with_orphans(vec![
        orphan(ROLE, ORPHANED, 3_000),
        orphan(ROLE, OTHER_ORPHANED, 2_900),
    ]));
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let roles = vec![role(ROLE, &[ORPHANED, OTHER_ORPHANED, KEPT])];

    handler(
        &store,
        roles,
        Arc::<FakeIamUnitOfWork>::clone(&unit_of_work),
    )
    .handle(command())
    .await
    .unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed.len(), 1);
    let audits = committed[0].audits(PolicyVersion::new(1).unwrap());
    assert_eq!(audits.len(), 2);
    let summaries: Vec<String> = audits
        .iter()
        .map(|audit| audit.parts().before.as_ref().unwrap().as_str().to_owned())
        .collect();
    assert!(summaries[0].contains(ORPHANED), "{summaries:?}");
    assert!(summaries[1].contains(OTHER_ORPHANED), "{summaries:?}");
    let ids: Vec<_> = audits.iter().map(|audit| audit.parts().id).collect();
    assert_ne!(ids[0], ids[1]);
    let ChangeStatement::SaveRole(statement) = &committed[0].parts().statements[0] else {
        panic!("a role statement expected");
    };
    assert_eq!(statement.role().grants.len(), 1);
    assert!(statement.role().grants.contains(&grant(KEPT)));
}

#[tokio::test]
async fn each_role_with_expired_grants_is_changed_on_its_own() {
    let store = Arc::new(FakeMaintenanceStore::new().with_orphans(vec![
        orphan(ROLE, ORPHANED, 3_000),
        orphan(OTHER_ROLE, ORPHANED, 2_900),
    ]));
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let roles = vec![role(ROLE, &[ORPHANED, KEPT]), role(OTHER_ROLE, &[ORPHANED])];

    handler(
        &store,
        roles,
        Arc::<FakeIamUnitOfWork>::clone(&unit_of_work),
    )
    .handle(command())
    .await
    .unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed.len(), 2);
    assert_eq!(unit_of_work.policy_version(), 2);
    let targets: Vec<String> = committed
        .iter()
        .map(|change| change.parts().audit.parts().target.target_id().to_owned())
        .collect();
    assert_eq!(targets, [ROLE, OTHER_ROLE]);
}

#[tokio::test]
async fn a_role_that_is_gone_or_no_longer_holds_the_grant_needs_no_change() {
    let store = Arc::new(FakeMaintenanceStore::new().with_orphans(vec![
        orphan(ROLE, ORPHANED, 3_000),
        orphan(OTHER_ROLE, ORPHANED, 2_900),
    ]));
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let roles = vec![role(OTHER_ROLE, &[KEPT])];

    handler(
        &store,
        roles,
        Arc::<FakeIamUnitOfWork>::clone(&unit_of_work),
    )
    .handle(command())
    .await
    .unwrap();

    assert_eq!(unit_of_work.committed().len(), 0);
    assert_eq!(store.anchors().len(), 1);
}

#[tokio::test]
async fn a_role_that_changed_meanwhile_keeps_its_grants_and_the_pass_goes_on() {
    let store =
        Arc::new(FakeMaintenanceStore::new().with_orphans(vec![orphan(ROLE, ORPHANED, 3_000)]));
    let roles = vec![role(ROLE, &[ORPHANED, KEPT])];

    handler(&store, roles, Arc::new(ConflictingUnitOfWork))
        .handle(command())
        .await
        .unwrap();

    assert_eq!(store.cutoffs().len(), 1);
    assert_eq!(store.anchors().len(), 1);
}

#[tokio::test]
async fn the_pass_anchors_the_chain_once_with_the_time_of_the_pass() {
    let head = AuditChainHead::new(12, AuditHash::new(&[7; AuditHash::LENGTH]).unwrap()).unwrap();
    let store = Arc::new(
        FakeMaintenanceStore::new()
            .with_purged(PurgedRecords {
                idempotency_records: 4,
                change_receipts: 5,
                inbound_events: 6,
            })
            .with_head(head),
    );

    handler(&store, Vec::new(), Arc::new(FakeIamUnitOfWork::new()))
        .handle(command())
        .await
        .unwrap();

    let anchors = store.anchors();
    assert_eq!(anchors.len(), 1);
    assert_eq!(anchors[0].occurred_at, at());
}

#[tokio::test]
async fn a_store_that_cannot_find_the_orphaned_grants_fails_the_pass_before_anything_is_removed() {
    let store = Arc::new(FakeMaintenanceStore::new().failing(Failing::Orphans));

    let error = handler(&store, Vec::new(), Arc::new(FakeIamUnitOfWork::new()))
        .handle(command())
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
    assert_eq!(store.cutoffs().len(), 0);
    assert_eq!(store.anchors().len(), 0);
}

#[tokio::test]
async fn a_store_that_cannot_purge_the_records_fails_the_pass_before_the_anchoring() {
    let store = Arc::new(FakeMaintenanceStore::new().failing(Failing::Purge));

    let error = handler(&store, Vec::new(), Arc::new(FakeIamUnitOfWork::new()))
        .handle(command())
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
    assert_eq!(store.anchors().len(), 0);
}

#[tokio::test]
async fn a_store_that_cannot_anchor_the_chain_fails_the_pass() {
    let store = Arc::new(FakeMaintenanceStore::new().failing(Failing::Anchor));

    let error = handler(&store, Vec::new(), Arc::new(FakeIamUnitOfWork::new()))
        .handle(command())
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}

#[tokio::test]
async fn a_unit_of_work_that_fails_fails_the_pass_before_the_records_are_removed() {
    let store =
        Arc::new(FakeMaintenanceStore::new().with_orphans(vec![orphan(ROLE, ORPHANED, 3_000)]));
    let roles = vec![role(ROLE, &[ORPHANED])];

    let error = handler(&store, roles, Arc::new(FakeIamUnitOfWork::failing()))
        .handle(command())
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
    assert_eq!(store.cutoffs().len(), 0);
    assert_eq!(store.anchors().len(), 0);
}

#[tokio::test]
async fn a_role_repository_that_fails_fails_the_pass() {
    let store =
        Arc::new(FakeMaintenanceStore::new().with_orphans(vec![orphan(ROLE, ORPHANED, 3_000)]));
    let handler = RunMaintenanceCommandHandler::new(
        Arc::<FakeMaintenanceStore>::clone(&store),
        Arc::new(FakeRoleRepository::failing()),
        Arc::new(FakeIamUnitOfWork::new()),
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );

    let error = handler.handle(command()).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
    assert_eq!(store.anchors().len(), 0);
}
