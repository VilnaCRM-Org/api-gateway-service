use std::time::{Duration, SystemTime};

use iam_domain::{
    AnchorStamp, AuditChainHead, AuditHash, ExpiredOrphanedGrant, MaintenanceStore as _,
    PermissionGrant, PurgedRecords, RepositoryError, RetentionCutoffs, RoleId,
};
use shared_domain::Uuid;

use super::{Failing, FakeMaintenanceStore};
use crate::block_on;

const ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";
const EVENT: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ae";

fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(secs))
        .unwrap()
}

fn orphan(key: &str, orphaned_secs: u64) -> ExpiredOrphanedGrant {
    ExpiredOrphanedGrant {
        role_id: RoleId::parse(ROLE).unwrap(),
        grant: PermissionGrant::parse(key).unwrap(),
        orphaned_at: at(orphaned_secs),
    }
}

fn stamp() -> AnchorStamp {
    AnchorStamp {
        event_id: Uuid::parse(EVENT).unwrap(),
        occurred_at: at(9),
    }
}

#[test]
fn only_grants_orphaned_strictly_before_the_instant_are_found_oldest_first_up_to_the_limit() {
    let store = FakeMaintenanceStore::new().with_orphans(vec![
        orphan("rest:core:GET /b", 30),
        orphan("rest:core:GET /a", 10),
        orphan("rest:core:GET /c", 20),
        orphan("rest:core:GET /d", 50),
    ]);

    let found = block_on(store.expired_orphaned_grants(at(50), 2)).unwrap();

    assert_eq!(
        found,
        [
            orphan("rest:core:GET /a", 10),
            orphan("rest:core:GET /c", 20)
        ]
    );
    assert_eq!(store.orphan_requests(), [(at(50), 2)]);
}

#[test]
fn a_purge_reports_the_configured_counts_and_keeps_its_cutoffs() {
    let purged = PurgedRecords {
        idempotency_records: 1,
        change_receipts: 2,
        inbound_events: 3,
    };
    let store = FakeMaintenanceStore::default().with_purged(purged);
    let cutoffs = RetentionCutoffs::at(at(200_000), Duration::from_hours(1));

    let reported = block_on(store.purge_expired_records(&cutoffs)).unwrap();

    assert_eq!(reported, purged);
    assert_eq!(store.cutoffs(), [cutoffs]);
}

#[test]
fn an_anchoring_returns_the_head_and_keeps_its_stamp() {
    let head = AuditChainHead::new(7, AuditHash::new(&[1; AuditHash::LENGTH]).unwrap()).unwrap();
    let store = FakeMaintenanceStore::new().with_head(head);

    let anchored = block_on(store.anchor_audit_chain(stamp())).unwrap();

    assert_eq!(anchored, head);
    assert_eq!(store.anchors(), [stamp()]);
}

#[test]
fn a_failing_operation_answers_unavailable_and_the_others_work() {
    let cutoffs = RetentionCutoffs::at(at(200_000), Duration::from_hours(1));
    let orphans = FakeMaintenanceStore::new().failing(Failing::Orphans);
    let purge = FakeMaintenanceStore::new().failing(Failing::Purge);
    let anchor = FakeMaintenanceStore::new().failing(Failing::Anchor);

    assert!(matches!(
        block_on(orphans.expired_orphaned_grants(at(1), 1)),
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(block_on(orphans.purge_expired_records(&cutoffs)).is_ok());
    assert!(matches!(
        block_on(purge.purge_expired_records(&cutoffs)),
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        block_on(anchor.anchor_audit_chain(stamp())),
        Err(RepositoryError::Unavailable(_))
    ));
    assert_eq!(anchor.anchors().len(), 0);
    assert!(block_on(purge.anchor_audit_chain(stamp())).is_ok());
}
