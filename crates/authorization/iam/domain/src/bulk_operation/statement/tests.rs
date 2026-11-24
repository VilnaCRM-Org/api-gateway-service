use std::time::{Duration, SystemTime};

use shared_domain::Uuid;

use super::BulkProgressStatement;
use crate::bulk_operation::{BulkKind, BulkOperation, BulkStamp, BulkStatus};
use crate::value_object::actor_ref::{ActorRef, SystemComponent};
use crate::value_object::identifier::BulkOperationId;
use crate::value_object::policy_version::PolicyVersion;

fn operation() -> BulkOperation {
    let id = BulkOperationId::parse("01890a5d-ac96-774b-bcce-b302099a8058").unwrap();
    BulkOperation::pending(
        id,
        BulkKind::RoleDeletion,
        10,
        ActorRef::System(SystemComponent::Startup),
        SystemTime::UNIX_EPOCH,
    )
    .unwrap()
}

#[test]
fn the_statement_holds_the_state_after_the_chunk_and_the_progress_before_it() {
    let mut operation = operation();
    let stamp = BulkStamp {
        event_id: Uuid::parse("01890a5d-ac96-774b-bcce-b302099a8057").unwrap(),
        occurred_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(5))
            .unwrap(),
    };
    operation
        .record_chunk(4, PolicyVersion::new(7).unwrap(), stamp)
        .unwrap();

    let statement = BulkProgressStatement::after_chunk(&operation, 0);

    assert_eq!(statement.expected_applied(), 0);
    assert_eq!(statement.operation().applied_records, 4);
    assert_eq!(statement.operation().status, BulkStatus::Running);
    assert_eq!(
        statement.operation().last_version,
        Some(PolicyVersion::new(7).unwrap())
    );
}
