//! Values and doubles that the tests of the revocation writes of the REST and GraphQL adapters
//! share.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use iam_domain::{ActorRef, AuditTarget, ChangeId, ChangeReceipt, EntityVersion, PolicyVersion};
use shared_domain::{Command, CommandBus, QueryBus, Uuid};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::request_digester::FakeRequestDigester;

use crate::error::IamError;
use crate::fixtures::USER;
use crate::http::IamState;
use crate::query::get_change_receipt::GetChangeReceiptQuery;
use crate::query::get_idempotent_replay::GetIdempotentReplayQuery;

/// The target that every receipt names.
pub(crate) const TARGET: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ce";

/// A bus error that a test builds when it needs it.
pub(crate) type Refusal = fn() -> IamError;

/// The receipt of the committed revocation of the fixtures.
pub(crate) fn receipt() -> ChangeReceipt {
    ChangeReceipt::new(
        ChangeId::parse(TARGET).unwrap(),
        ActorRef::User(Uuid::parse(USER).unwrap()),
        AuditTarget::new("session_revocation", TARGET).unwrap(),
        EntityVersion::INITIAL,
        Some(PolicyVersion::new(41).unwrap()),
    )
}

/// What the doubles answer.
pub(crate) struct Answers {
    /// The receipt that the idempotent-replay query finds, when it finds one.
    pub replay: Option<ChangeReceipt>,
    /// The answer of the command.
    pub command: Result<(), Refusal>,
}

impl Default for Answers {
    fn default() -> Self {
        Self {
            replay: None,
            command: Ok(()),
        }
    }
}

/// The commands that were dispatched.
pub(crate) type Dispatched<C> = Arc<Mutex<Vec<C>>>;

/// The commands that were dispatched, in order.
pub(crate) fn recorded<C: Clone>(dispatched: &Dispatched<C>) -> Vec<C> {
    dispatched
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// The state over doubles that answer as `answers` say, with the log of the dispatched commands of
/// type `C`.
pub(crate) fn scenario<C>(answers: Answers) -> (IamState, Dispatched<C>)
where
    C: Command<Error = IamError> + Clone,
{
    let dispatched = Dispatched::<C>::default();
    let sink = Arc::clone(&dispatched);
    let Answers { replay, command } = answers;
    let command_bus: Arc<dyn CommandBus> = Arc::new(FakeCommandBus::handling(move |sent: C| {
        sink.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(sent);
        command.map_err(|refusal| refusal())
    }));
    let query_bus: Arc<dyn QueryBus> = Arc::new(
        FakeQueryBus::answering(move |_query: GetIdempotentReplayQuery| Ok(replay.clone()))
            .and_answering(move |_query: GetChangeReceiptQuery| Ok(receipt())),
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
