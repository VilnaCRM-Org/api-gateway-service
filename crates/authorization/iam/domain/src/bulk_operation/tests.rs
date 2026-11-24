use std::time::{Duration, SystemTime};

use rstest::rstest;
use shared_domain::Uuid;

use super::{
    BulkKind, BulkOperation, BulkOperationParts, BulkOperationRefused, BulkStamp, BulkStatus,
    InvalidBulkOperation,
};
use crate::value_object::actor_ref::{ActorRef, SystemComponent};
use crate::value_object::event_data::EventValue;
use crate::value_object::identifier::BulkOperationId;
use crate::value_object::policy_version::PolicyVersion;

const EVENT: &str = "01890a5d-ac96-774b-bcce-b302099a8057";
const OPERATION: &str = "01890a5d-ac96-774b-bcce-b302099a8058";

fn id() -> BulkOperationId {
    BulkOperationId::parse(OPERATION).unwrap()
}

fn actor() -> ActorRef {
    ActorRef::System(SystemComponent::Startup)
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(1_700_000_000))
        .and_then(|base| base.checked_add(Duration::from_secs(seconds)))
        .unwrap()
}

fn stamp(seconds: u64) -> BulkStamp {
    BulkStamp {
        event_id: Uuid::parse(EVENT).unwrap(),
        occurred_at: at(seconds),
    }
}

fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

fn pending(total: u64) -> BulkOperation {
    BulkOperation::pending(id(), BulkKind::RoleDeletion, total, actor(), at(0)).unwrap()
}

#[test]
fn a_pending_operation_has_applied_nothing() {
    let operation = pending(2_500);

    let parts = operation.parts();
    assert_eq!(parts.status, BulkStatus::Pending);
    assert_eq!(parts.total_records, 2_500);
    assert_eq!(parts.applied_records, 0);
    assert_eq!(parts.first_version, None);
    assert_eq!(parts.last_version, None);
    assert_eq!(parts.kind, BulkKind::RoleDeletion);
    assert_eq!(operation.remaining_records(), 2_500);
}

#[test]
fn an_operation_without_records_is_refused() {
    let error = BulkOperation::pending(id(), BulkKind::Other, 0, actor(), at(0)).unwrap_err();

    assert_eq!(error, InvalidBulkOperation::NoRecords);
}

#[test]
fn chunks_advance_the_progress_and_the_last_one_completes_with_an_event() {
    let mut operation = pending(2_500);

    operation
        .record_chunk(1_000, version(11), stamp(1))
        .unwrap();
    assert_eq!(operation.parts().status, BulkStatus::Running);
    assert_eq!(
        operation.pull_envelopes().unwrap(),
        Vec::<crate::EventEnvelope>::new()
    );
    operation
        .record_chunk(1_000, version(12), stamp(2))
        .unwrap();
    operation.record_chunk(500, version(13), stamp(3)).unwrap();

    let parts = operation.parts();
    assert_eq!(parts.status, BulkStatus::Completed);
    assert_eq!(parts.applied_records, 2_500);
    assert_eq!(parts.first_version, Some(version(11)));
    assert_eq!(parts.last_version, Some(version(13)));
    assert_eq!(parts.updated_at, at(3));
    let envelopes = operation.pull_envelopes().unwrap();
    assert_eq!(envelopes.len(), 1);
    let envelope = &envelopes[0];
    assert_eq!(
        envelope.parts().event_type.as_str(),
        "iam.bulk_operation.completed"
    );
    assert_eq!(envelope.parts().aggregate_id, id().as_uuid());
    let fields = envelope.parts().data.fields();
    assert!(fields.contains(&(
        "kind".to_owned(),
        EventValue::Text("role_deletion".to_owned())
    )));
    assert!(fields.contains(&("totalRecords".to_owned(), EventValue::Integer(2_500))));
    assert!(fields.contains(&("firstVersion".to_owned(), EventValue::Integer(11))));
    assert!(fields.contains(&("lastVersion".to_owned(), EventValue::Integer(13))));
}

#[test]
fn a_finished_operation_accepts_no_more_chunks() {
    let mut operation = pending(1);
    operation.record_chunk(1, version(1), stamp(1)).unwrap();

    let error = operation.record_chunk(1, version(2), stamp(2)).unwrap_err();

    assert_eq!(error, BulkOperationRefused::Finished);
    assert_eq!(
        operation.fail("late", at(3)),
        Err(BulkOperationRefused::Finished)
    );
}

#[rstest]
#[case(0)]
#[case(11)]
fn a_chunk_must_fit_the_remaining_records(#[case] records: u64) {
    let mut operation = pending(10);

    let error = operation
        .record_chunk(records, version(1), stamp(1))
        .unwrap_err();

    assert_eq!(error, BulkOperationRefused::ChunkSize);
    assert_eq!(operation.parts().applied_records, 0);
}

#[rstest]
#[case(5)]
#[case(4)]
fn a_chunk_version_must_exceed_the_previous_one(#[case] second: i64) {
    let mut operation = pending(10);
    operation.record_chunk(3, version(5), stamp(1)).unwrap();

    let error = operation
        .record_chunk(3, version(second), stamp(2))
        .unwrap_err();

    assert_eq!(error, BulkOperationRefused::VersionOrder);
    assert_eq!(operation.parts().applied_records, 3);
}

#[test]
fn a_failed_operation_keeps_a_bounded_reason() {
    let mut operation = pending(10);

    operation.fail(&"x".repeat(900), at(4)).unwrap();

    let parts = operation.parts();
    assert_eq!(parts.status, BulkStatus::Failed);
    assert_eq!(parts.error.as_ref().unwrap().chars().count(), 500);
    assert_eq!(parts.updated_at, at(4));
    assert!(parts.status.is_finished());
}

fn stored(applied: u64, first: Option<i64>, last: Option<i64>) -> BulkOperationParts {
    BulkOperationParts {
        id: id(),
        kind: BulkKind::Resync,
        status: BulkStatus::Running,
        total_records: 10,
        applied_records: applied,
        first_version: first.map(version),
        last_version: last.map(version),
        requester: actor(),
        error: None,
        created_at: at(0),
        updated_at: at(1),
    }
}

#[test]
fn a_consistent_stored_state_is_restored_without_events() {
    let mut operation = BulkOperation::restore(stored(4, Some(2), Some(3))).unwrap();

    assert_eq!(operation.remaining_records(), 6);
    assert_eq!(
        operation.pull_envelopes().unwrap(),
        Vec::<crate::EventEnvelope>::new()
    );
    assert!(BulkOperation::restore(stored(0, None, None)).is_ok());
}

#[rstest]
#[case(stored(11, Some(1), Some(2)))]
#[case(stored(4, Some(3), Some(2)))]
#[case(stored(4, Some(3), None))]
#[case(stored(4, None, Some(3)))]
fn an_inconsistent_stored_state_is_refused(#[case] parts: BulkOperationParts) {
    assert_eq!(
        BulkOperation::restore(parts).unwrap_err(),
        InvalidBulkOperation::Progress
    );
}

#[test]
fn a_stored_state_without_records_is_refused() {
    let mut parts = stored(0, None, None);
    parts.total_records = 0;

    assert_eq!(
        BulkOperation::restore(parts).unwrap_err(),
        InvalidBulkOperation::NoRecords
    );
}

#[rstest]
#[case(BulkKind::RoleDeletion, "role_deletion")]
#[case(BulkKind::Catalogue, "catalogue")]
#[case(BulkKind::Resync, "resync")]
#[case(BulkKind::Other, "other")]
fn kinds_round_trip_through_their_text(#[case] kind: BulkKind, #[case] text: &str) {
    assert_eq!(kind.as_str(), text);
    assert_eq!(BulkKind::parse(text), Ok(kind));
}

#[rstest]
#[case(BulkStatus::Pending, "pending", false)]
#[case(BulkStatus::Running, "running", false)]
#[case(BulkStatus::Completed, "completed", true)]
#[case(BulkStatus::Failed, "failed", true)]
fn statuses_round_trip_through_their_text(
    #[case] status: BulkStatus,
    #[case] text: &str,
    #[case] finished: bool,
) {
    assert_eq!(status.as_str(), text);
    assert_eq!(BulkStatus::parse(text), Ok(status));
    assert_eq!(status.is_finished(), finished);
}

#[test]
fn unknown_texts_are_refused() {
    assert_eq!(BulkKind::parse("bulk"), Err(InvalidBulkOperation::Kind));
    assert_eq!(BulkStatus::parse("done"), Err(InvalidBulkOperation::Status));
}
