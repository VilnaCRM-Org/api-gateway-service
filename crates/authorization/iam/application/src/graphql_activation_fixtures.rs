//! Values and doubles that the tests of the activation of GraphQL specifications of the REST and
//! GraphQL adapters share.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use iam_domain::{
    ActorRef, AuditTarget, ChangeId, ChangeReceipt, EntityVersion, PermissionKey, PolicyVersion,
    SpecStatus,
};
use shared_domain::{CommandBus, QueryBus, Uuid};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::policy_epoch::seeded_policy_epoch;
use test_support::request_digester::FakeRequestDigester;

use crate::command::create_graphql_permissions::CreateGraphQlPermissionsCommand;
use crate::error::IamError;
use crate::fixtures::USER;
use crate::graphql_spec_fixtures::{SPEC, summary};
use crate::http::IamState;
use crate::query::get_change_receipt::GetChangeReceiptQuery;
use crate::query::get_graphql_permissions_created::GetGraphQlPermissionsCreatedQuery;
use crate::query::get_graphql_spec::GetGraphQlSpecQuery;
use crate::query::get_graphql_specs::GraphQlSpecSummary;
use crate::query::get_idempotent_replay::GetIdempotentReplayQuery;
use crate::query::get_policy_epoch::GetPolicyEpochQuery;

/// The change that every receipt names.
const CHANGE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ce";
/// The key that every answer lists as created.
pub(crate) const CREATED: &str = "gql:billing:Query.invoices";

/// A bus error that a test builds when it needs it.
pub(crate) type Refusal = fn() -> IamError;

/// The receipt of an activation of the version that every answer names.
pub(crate) fn receipt(policy_version: Option<i64>) -> ChangeReceipt {
    ChangeReceipt::new(
        ChangeId::parse(CHANGE).unwrap(),
        ActorRef::User(Uuid::parse(USER).unwrap()),
        AuditTarget::new("graphql_spec", SPEC).unwrap(),
        EntityVersion::INITIAL,
        policy_version.map(|value| PolicyVersion::new(value).unwrap()),
    )
}

/// The version of every answer, active.
pub(crate) fn active_summary() -> GraphQlSpecSummary {
    let mut active = summary();
    active.spec.status = SpecStatus::Active;
    active.spec.activated_at = Some(SystemTime::UNIX_EPOCH);
    active
}

/// What the doubles answer.
pub(crate) struct Answers {
    /// The answer of the version query.
    pub spec: Result<Option<GraphQlSpecSummary>, Refusal>,
    /// The receipt that the idempotent-replay query finds, when it finds one.
    pub replay: Option<ChangeReceipt>,
    /// The answer of the activation command.
    pub command: Result<(), Refusal>,
    /// The answer of the change-receipt query.
    pub receipt: ChangeReceipt,
    /// The keys that the activation created.
    pub created: Vec<PermissionKey>,
}

impl Default for Answers {
    fn default() -> Self {
        Self {
            spec: Ok(Some(summary())),
            replay: None,
            command: Ok(()),
            receipt: receipt(Some(7)),
            created: vec![PermissionKey::parse(CREATED).unwrap()],
        }
    }
}

/// The values a double recorded.
pub(crate) type Log<T> = Arc<Mutex<Vec<T>>>;

/// The values a double recorded, in order.
pub(crate) fn recorded<T: Clone>(log: &Log<T>) -> Vec<T> {
    log.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

fn push<T>(log: &Log<T>, value: T) {
    log.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(value);
}

/// The state over doubles that answer as `answers` say, with the log of the dispatched commands.
pub(crate) fn scenario(answers: Answers) -> (IamState, Log<CreateGraphQlPermissionsCommand>) {
    let commands: Log<CreateGraphQlPermissionsCommand> = Arc::default();
    let sink = Arc::clone(&commands);
    let Answers {
        spec,
        replay,
        command,
        receipt,
        created,
    } = answers;
    let command_bus: Arc<dyn CommandBus> = Arc::new(FakeCommandBus::handling(
        move |dispatched: CreateGraphQlPermissionsCommand| {
            push(&sink, dispatched);
            command.map_err(|refusal| refusal())
        },
    ));
    let query_bus: Arc<dyn QueryBus> = Arc::new(
        FakeQueryBus::answering(move |_query: GetGraphQlSpecQuery| {
            spec.clone().map_err(|refusal| refusal())
        })
        .and_answering(move |_query: GetIdempotentReplayQuery| Ok(replay.clone()))
        .and_answering(move |_query: GetChangeReceiptQuery| Ok(receipt.clone()))
        .and_answering(move |_query: GetGraphQlPermissionsCreatedQuery| Ok(created.clone()))
        .and_answering(|_query: GetPolicyEpochQuery| Ok(seeded_policy_epoch())),
    );
    let state = IamState {
        command_bus,
        query_bus,
        uuid_generator: Arc::new(SequenceUuidGenerator::starting_at(1)),
        clock: Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        request_digester: Arc::new(FakeRequestDigester),
    };
    (state, commands)
}
