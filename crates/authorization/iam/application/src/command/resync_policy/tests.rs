use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AuditOutcome, AuditSummary, BulkKind, BulkStatus, ChangeId, ChangeStatement,
    DecisionEffect, EventValue, IamUnitOfWork, IdempotencyKey, IdempotencyRequest, InventoryEntry,
    LogEpoch, PolicyDigestValue, PolicyEpoch, PolicyEpochRepository, PolicyLogTail,
    PolicyStateInventory, PolicyVersion, RelayEpoch, RequestDigest, RoleId, StateKey,
};
use shared_domain::{Command as _, CommandHandler as _, Uuid};
use test_support::anti_entropy::{FakePolicyLogTail, TextHeadCodec, head_record};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::policy_epoch::FakePolicyEpochRepository;
use test_support::policy_state_inventory::FakePolicyStateInventory;
use test_support::unit_of_work::FakeIamUnitOfWork;

use super::{ResyncPolicyCommand, ResyncPolicyCommandHandler, ResyncPolicyPorts};
use crate::error::IamError;
use crate::policy_topic_head::PolicyTopicHead;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const CHANGE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ac";

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn actor() -> ActorRef {
    ActorRef::User(Uuid::parse(USER).unwrap())
}

fn command(reason: &str) -> ResyncPolicyCommand {
    ResyncPolicyCommand {
        change_id: ChangeId::parse(CHANGE).unwrap(),
        actor: actor(),
        reason: reason.to_owned(),
        idempotency: None,
    }
}

fn epoch(version: i64, log_epoch: i64) -> PolicyEpoch {
    PolicyEpoch::new(
        PolicyVersion::new(version).unwrap(),
        PolicyDigestValue::ZERO,
        LogEpoch::new(log_epoch).unwrap(),
        RelayEpoch::ZERO,
        0,
    )
    .unwrap()
}

fn entries(count: u128) -> Vec<InventoryEntry> {
    (1..=count)
        .map(|number| {
            let id = RoleId::parse(&format!("0190f2a8-7b3c-7d4e-8f40-{number:012x}")).unwrap();
            InventoryEntry::State(StateKey::Role(id))
        })
        .collect()
}

struct Doubles {
    epochs: Arc<dyn PolicyEpochRepository>,
    inventory: Arc<dyn PolicyStateInventory>,
    tail: FakePolicyLogTail,
    unit_of_work: Arc<FakeIamUnitOfWork>,
}

impl Doubles {
    fn standard() -> Self {
        Self {
            epochs: Arc::new(FakePolicyEpochRepository::holding(epoch(40, 2))),
            inventory: Arc::new(FakePolicyStateInventory::holding(entries(5))),
            tail: FakePolicyLogTail::with(vec![head_record(0, 40, PolicyDigestValue::ZERO, 1)]),
            unit_of_work: Arc::new(FakeIamUnitOfWork::new()),
        }
    }

    fn handler(self) -> (ResyncPolicyCommandHandler, Arc<FakeIamUnitOfWork>) {
        let tail: Arc<dyn PolicyLogTail> = Arc::new(self.tail);
        let unit_of_work: Arc<dyn IamUnitOfWork> =
            Arc::<FakeIamUnitOfWork>::clone(&self.unit_of_work);
        let handler = ResyncPolicyCommandHandler::new(ResyncPolicyPorts {
            epochs: self.epochs,
            inventory: self.inventory,
            topic: PolicyTopicHead::new(tail, Arc::new(TextHeadCodec)),
            unit_of_work,
            clock: Arc::new(FixedClock::at(at())),
            ids: Arc::new(SequenceUuidGenerator::starting_at(1)),
        });
        (handler, self.unit_of_work)
    }
}

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(ResyncPolicyCommand::NAME, "ResyncPolicyCommand");
}

#[tokio::test]
async fn a_resync_is_one_change_that_starts_a_new_epoch_and_records_a_pending_operation() {
    let (handler, unit_of_work) = Doubles::standard().handler();

    handler.handle(command("topic lost records")).await.unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed.len(), 1);
    let parts = committed[0].parts();
    assert_eq!(parts.change_id, command("x").change_id);
    assert_eq!(parts.effect, DecisionEffect::Affected);
    let [ChangeStatement::StartResync(start)] = parts.statements.as_slice() else {
        panic!("one resync start expected: {:?}", parts.statements);
    };
    assert_eq!(start.epoch().from().value(), 2);
    assert_eq!(start.epoch().to().value(), 3);
    let operation = start.operation();
    assert_eq!(operation.id.as_uuid(), command("x").change_id.as_uuid());
    assert_eq!(operation.kind, BulkKind::Resync);
    assert_eq!(operation.status, BulkStatus::Pending);
    assert_eq!(operation.total_records, 5);
    assert_eq!(operation.requester, actor());
    assert_eq!(operation.created_at, at());
}

#[tokio::test]
async fn the_version_floor_is_the_higher_of_the_stored_version_and_the_topic_maximum() {
    let mut doubles = Doubles::standard();
    doubles.tail = FakePolicyLogTail::with(vec![head_record(0, 95, PolicyDigestValue::ZERO, 1)]);
    let (handler, unit_of_work) = doubles.handler();

    handler.handle(command("ahead")).await.unwrap();

    let committed = unit_of_work.committed();
    let [ChangeStatement::StartResync(start)] = committed[0].parts().statements.as_slice() else {
        panic!("one resync start expected");
    };
    assert_eq!(start.epoch().version_floor().value(), 95);
}

#[tokio::test]
async fn a_topic_below_postgresql_or_without_a_head_leaves_the_stored_version_as_the_floor() {
    for tail in [
        FakePolicyLogTail::with(vec![head_record(0, 7, PolicyDigestValue::ZERO, 1)]),
        FakePolicyLogTail::with(Vec::new()),
    ] {
        let mut doubles = Doubles::standard();
        doubles.tail = tail;
        let (handler, unit_of_work) = doubles.handler();

        handler.handle(command("behind")).await.unwrap();

        let committed = unit_of_work.committed();
        let [ChangeStatement::StartResync(start)] = committed[0].parts().statements.as_slice()
        else {
            panic!("one resync start expected");
        };
        assert_eq!(start.epoch().version_floor().value(), 40);
    }
}

#[tokio::test]
async fn the_event_names_the_epoch_the_versions_the_reason_and_the_operation() {
    let (handler, unit_of_work) = Doubles::standard().handler();

    handler
        .handle(command("  topic lost records  "))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let [event] = committed[0].parts().events.as_slice() else {
        panic!("one event expected");
    };
    assert_eq!(event.parts().event_type.as_str(), "iam.policy.resynced");
    assert_eq!(event.parts().actor, actor());
    assert_eq!(event.parts().aggregate_id, command("x").change_id.as_uuid());
    let fields = event.parts().data.fields();
    let field = |name: &str| {
        fields
            .iter()
            .find(|(key, _value)| key == name)
            .unwrap()
            .1
            .clone()
    };
    assert_eq!(field("logEpoch"), EventValue::Integer(3));
    assert_eq!(field("fromVersion"), EventValue::Integer(40));
    assert_eq!(field("toVersion"), EventValue::Integer(41));
    assert_eq!(
        field("reason"),
        EventValue::Text("topic lost records".to_owned())
    );
    assert_eq!(
        field("bulkOperationId"),
        EventValue::Text(CHANGE.to_owned())
    );
}

#[tokio::test]
async fn the_audit_record_is_committed_names_the_operation_and_holds_the_reason() {
    let (handler, unit_of_work) = Doubles::standard().handler();

    handler.handle(command("topic lost records")).await.unwrap();

    let committed = unit_of_work.committed();
    let audit = committed[0].parts().audit.parts();
    assert_eq!(audit.outcome, AuditOutcome::Committed);
    assert_eq!(audit.action.as_str(), "policy.resync");
    assert_eq!(audit.target.target_type(), "bulk_operation");
    assert_eq!(audit.target.target_id(), CHANGE);
    assert_eq!(audit.actor, actor());
    assert_eq!(
        audit.before.as_ref().map(AuditSummary::as_str),
        Some("logEpoch=2 version=40")
    );
    let after = audit.after.as_ref().unwrap().as_str();
    assert!(after.contains("logEpoch=3 firstVersion=41 records=5"));
    assert!(after.ends_with("reason=topic lost records"));
}

#[tokio::test]
async fn the_idempotency_key_travels_with_the_change_and_the_audit_record() {
    let (handler, unit_of_work) = Doubles::standard().handler();
    let mut command = command("again");
    command.idempotency = Some(IdempotencyRequest {
        key: IdempotencyKey::new("resync-1").unwrap(),
        request_digest: RequestDigest::new(&[7; RequestDigest::LENGTH]).unwrap(),
    });

    handler.handle(command).await.unwrap();

    let committed = unit_of_work.committed();
    let record = committed[0].idempotency_record().unwrap();
    assert_eq!(record.key().as_str(), "resync-1");
    assert_eq!(
        committed[0]
            .parts()
            .audit
            .parts()
            .idempotency_key
            .as_ref()
            .map(IdempotencyKey::as_str),
        Some("resync-1")
    );
}

#[tokio::test]
async fn a_reason_the_audit_log_would_refuse_is_an_invalid_reason() {
    for reason in ["first line\nsecond line", "   "] {
        let (handler, unit_of_work) = Doubles::standard().handler();

        let error = handler.handle(command(reason)).await.unwrap_err();

        let IamError::Invalid(violations) = error else {
            panic!("a validation error expected");
        };
        assert_eq!(violations[0].property_path, "reason");
        assert_eq!(unit_of_work.committed().len(), 0);
    }
}

#[tokio::test]
async fn a_policy_without_entities_cannot_be_resynced() {
    let mut doubles = Doubles::standard();
    doubles.inventory = Arc::new(FakePolicyStateInventory::new());
    let (handler, unit_of_work) = doubles.handler();

    let error = handler.handle(command("empty")).await.unwrap_err();

    assert!(matches!(error, IamError::Conflict));
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn a_failing_dependency_is_a_storage_failure_and_commits_nothing() {
    type Break = fn(&mut Doubles);
    let breaks: [Break; 4] = [
        |doubles| doubles.epochs = Arc::new(FakePolicyEpochRepository::failing()),
        |doubles| doubles.inventory = Arc::new(FakePolicyStateInventory::failing()),
        |doubles| doubles.tail = FakePolicyLogTail::with(Vec::new()).unavailable(),
        |doubles| doubles.unit_of_work = Arc::new(FakeIamUnitOfWork::failing()),
    ];
    for apply in breaks {
        let mut doubles = Doubles::standard();
        apply(&mut doubles);
        let (handler, unit_of_work) = doubles.handler();

        let error = handler.handle(command("failing")).await.unwrap_err();

        assert!(matches!(error, IamError::Storage(_)), "{error:?}");
        assert_eq!(unit_of_work.committed().len(), 0);
    }
}

#[tokio::test]
async fn a_topic_version_at_the_end_of_the_range_cannot_be_continued() {
    let mut doubles = Doubles::standard();
    doubles.tail =
        FakePolicyLogTail::with(vec![head_record(0, i64::MAX, PolicyDigestValue::ZERO, 1)]);
    let (handler, unit_of_work) = doubles.handler();

    let error = handler.handle(command("end")).await.unwrap_err();

    assert!(matches!(error, IamError::Conflict));
    assert_eq!(unit_of_work.committed().len(), 0);
}
