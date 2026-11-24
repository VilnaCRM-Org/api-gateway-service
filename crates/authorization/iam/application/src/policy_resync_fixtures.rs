//! Values and doubles that the tests of the policy resync of the REST and GraphQL adapters share.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AuditTarget, BulkKind, BulkOperationId, BulkOperationParts, BulkStatus, ChangeId,
    ChangeReceipt, EntityVersion, PolicyVersion,
};
use shared_domain::{CommandBus, QueryBus, Uuid};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::request_digester::FakeRequestDigester;

use crate::command::resync_policy::ResyncPolicyCommand;
use crate::error::IamError;
use crate::fixtures::USER;
use crate::http::IamState;
use crate::query::get_bulk_operation::GetBulkOperationQuery;
use crate::query::get_change_receipt::GetChangeReceiptQuery;
use crate::query::get_idempotent_replay::GetIdempotentReplayQuery;

/// The bulk operation that every receipt names.
pub(crate) const OPERATION: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ce";

/// A bus error that a test builds when it needs it.
pub(crate) type Refusal = fn() -> IamError;

/// The receipt of the resync that started the operation of the fixtures.
pub(crate) fn receipt() -> ChangeReceipt {
    ChangeReceipt::new(
        ChangeId::parse(OPERATION).unwrap(),
        ActorRef::User(Uuid::parse(USER).unwrap()),
        AuditTarget::new("bulk_operation", OPERATION).unwrap(),
        EntityVersion::INITIAL,
        Some(PolicyVersion::new(41).unwrap()),
    )
}

/// The pending resync of 2,500 records that every answer holds.
pub(crate) fn operation() -> BulkOperationParts {
    let at = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap();
    BulkOperationParts {
        id: BulkOperationId::parse(OPERATION).unwrap(),
        kind: BulkKind::Resync,
        status: BulkStatus::Pending,
        total_records: 2_500,
        applied_records: 0,
        first_version: None,
        last_version: None,
        requester: ActorRef::User(Uuid::parse(USER).unwrap()),
        error: None,
        created_at: at,
        updated_at: at,
    }
}

/// What the doubles answer.
pub(crate) struct Answers {
    /// The receipt that the idempotent-replay query finds, when it finds one.
    pub replay: Option<ChangeReceipt>,
    /// The answer of the resync command.
    pub command: Result<(), Refusal>,
    /// The answer of the bulk operation query.
    pub operation: Result<Option<BulkOperationParts>, Refusal>,
}

impl Default for Answers {
    fn default() -> Self {
        Self {
            replay: None,
            command: Ok(()),
            operation: Ok(Some(operation())),
        }
    }
}

/// The commands that were dispatched.
pub(crate) type Dispatched = Arc<Mutex<Vec<ResyncPolicyCommand>>>;

/// The commands that were dispatched, in order.
pub(crate) fn recorded(dispatched: &Dispatched) -> Vec<ResyncPolicyCommand> {
    dispatched
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// The state over doubles that answer as `answers` say, with the log of the dispatched commands.
pub(crate) fn scenario(answers: Answers) -> (IamState, Dispatched) {
    let dispatched = Dispatched::default();
    let sink = Arc::clone(&dispatched);
    let Answers {
        replay,
        command,
        operation,
    } = answers;
    let command_bus: Arc<dyn CommandBus> = Arc::new(FakeCommandBus::handling(
        move |sent: ResyncPolicyCommand| {
            sink.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(sent);
            command.map_err(|refusal| refusal())
        },
    ));
    let query_bus: Arc<dyn QueryBus> = Arc::new(
        FakeQueryBus::answering(move |_query: GetIdempotentReplayQuery| Ok(replay.clone()))
            .and_answering(move |_query: GetChangeReceiptQuery| Ok(receipt()))
            .and_answering(move |_query: GetBulkOperationQuery| {
                operation.clone().map_err(|refusal| refusal())
            }),
    );
    let state = IamState {
        command_bus,
        query_bus,
        uuid_generator: Arc::new(SequenceUuidGenerator::starting_at(1)),
        clock: Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        request_digester: Arc::new(FakeRequestDigester),
    };
    (state, dispatched)
}
