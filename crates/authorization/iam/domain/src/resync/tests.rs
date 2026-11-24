use std::time::{Duration, SystemTime};

use shared_domain::{DomainEvent as _, Uuid};

use super::{EpochChange, InventoryEntry, PolicyResynced, Republication, ResyncStart};
use crate::bulk_operation::{BulkKind, BulkOperation};
use crate::entity::event_envelope::{EventEnvelope, IamDomainEvent as _};
use crate::error::InvalidIamValue;
use crate::state::key::StateKey;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::audit_summary::AuditSummary;
use crate::value_object::event_data::EventValue;
use crate::value_object::identifier::{BulkOperationId, RoleId};
use crate::value_object::log_epoch::LogEpoch;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::service_name::ServiceName;

const EVENT: &str = "01890a5d-ac96-774b-bcce-b302099a8057";
const OPERATION: &str = "0192f6a0-0000-7000-8000-000000000001";
const ROLE: &str = "0192f6a0-0000-7000-8000-000000000002";

fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

fn epoch(value: i64) -> LogEpoch {
    LogEpoch::new(value).unwrap()
}

fn actor() -> ActorRef {
    ActorRef::User(Uuid::parse("3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a").unwrap())
}

fn resynced() -> PolicyResynced {
    PolicyResynced {
        event_id: Uuid::parse(EVENT).unwrap(),
        bulk_operation_id: BulkOperationId::parse(OPERATION).unwrap(),
        log_epoch: epoch(3),
        from_version: version(40),
        to_version: version(95),
        reason: AuditSummary::new("topic compacted after an incident").unwrap(),
        actor: actor(),
        occurred_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(1_700_000_000))
            .unwrap(),
    }
}

#[test]
fn an_epoch_change_moves_to_the_next_log_epoch_and_keeps_the_floor() {
    let change = EpochChange::new(epoch(2), version(95)).unwrap();

    assert_eq!(change.from(), epoch(2));
    assert_eq!(change.to(), epoch(3));
    assert_eq!(change.version_floor(), version(95));
}

#[test]
fn an_epoch_change_refuses_a_counter_that_cannot_grow() {
    assert_eq!(
        EpochChange::new(epoch(i64::MAX), version(1)),
        Err(InvalidIamValue::LogEpochNegative)
    );
}

#[test]
fn entries_split_into_the_keys_and_the_services_of_a_republication() {
    let role = StateKey::Role(RoleId::parse(ROLE).unwrap());
    let service = ServiceName::new("billing").unwrap();

    let republication = InventoryEntry::republication(vec![
        InventoryEntry::State(role.clone()),
        InventoryEntry::Catalogue(service.clone()),
    ]);

    assert_eq!(republication, Republication::new(vec![role], vec![service]));
}

#[test]
fn the_event_is_named_after_the_resync_and_keyed_by_the_bulk_operation() {
    let event = resynced();

    assert_eq!(event.event_name(), "iam.policy.resynced");
    assert_eq!(event.event_id(), Uuid::parse(EVENT).unwrap());
    assert_eq!(event.aggregate_id(), Uuid::parse(OPERATION).unwrap());
    assert_eq!(event.entity_version(), None);
    assert_eq!(event.actor(), &actor());
}

#[test]
fn the_data_carries_the_epoch_the_versions_the_reason_and_the_operation() {
    let data = resynced().data().unwrap();

    assert_eq!(
        data.fields(),
        [
            ("logEpoch".to_owned(), EventValue::Integer(3)),
            ("fromVersion".to_owned(), EventValue::Integer(40)),
            ("toVersion".to_owned(), EventValue::Integer(95)),
            (
                "reason".to_owned(),
                EventValue::Text("topic compacted after an incident".to_owned())
            ),
            (
                "bulkOperationId".to_owned(),
                EventValue::Text(OPERATION.to_owned())
            ),
        ]
    );
}

#[test]
fn the_event_can_be_enveloped_with_its_type() {
    let envelope = EventEnvelope::of(&resynced()).unwrap();

    assert_eq!(envelope.parts().event_type.as_str(), "iam.policy.resynced");
    assert_eq!(
        envelope.parts().aggregate_id,
        Uuid::parse(OPERATION).unwrap()
    );
}

#[test]
fn a_resync_start_holds_the_epoch_change_and_the_pending_operation() {
    let epoch = EpochChange::new(epoch(1), version(10)).unwrap();
    let operation = BulkOperation::pending(
        BulkOperationId::parse(OPERATION).unwrap(),
        BulkKind::Resync,
        4,
        actor(),
        SystemTime::UNIX_EPOCH,
    )
    .unwrap();

    let start = ResyncStart::new(epoch.clone(), operation.parts().clone());

    assert_eq!(start.epoch(), &epoch);
    assert_eq!(start.operation(), operation.parts());
}
