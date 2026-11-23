//! Values and doubles that the tests of the retirement of specification versions of the REST and
//! GraphQL adapters share.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use iam_domain::{
    ActorRef, AuditTarget, ChangeId, ChangeReceipt, EntityVersion, PolicyVersion, SpecStatus,
};
use shared_domain::{CommandBus, QueryBus, Uuid};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::policy_epoch::seeded_policy_epoch;
use test_support::request_digester::FakeRequestDigester;

use crate::command::retire_graphql_spec::RetireGraphQlSpecCommand;
use crate::command::retire_openapi_spec::RetireOpenApiSpecCommand;
use crate::error::IamError;
use crate::fixtures::USER;
use crate::graphql_spec_fixtures::{SPEC, summary as graphql_summary};
use crate::http::IamState;
use crate::openapi_spec_fixtures::summary as openapi_summary;
use crate::query::get_change_receipt::GetChangeReceiptQuery;
use crate::query::get_graphql_spec::GetGraphQlSpecQuery;
use crate::query::get_graphql_specs::GraphQlSpecSummary;
use crate::query::get_idempotent_replay::GetIdempotentReplayQuery;
use crate::query::get_openapi_spec::GetOpenApiSpecQuery;
use crate::query::get_openapi_specs::OpenApiSpecSummary;
use crate::query::get_policy_epoch::GetPolicyEpochQuery;

/// The change that every receipt names.
const CHANGE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ce";

/// A bus error that a test builds when it needs it.
pub(crate) type Refusal = fn() -> IamError;

/// The receipt of a retirement of the version that every answer names.
pub(crate) fn receipt(target_type: &str, policy_version: Option<i64>) -> ChangeReceipt {
    ChangeReceipt::new(
        ChangeId::parse(CHANGE).unwrap(),
        ActorRef::User(Uuid::parse(USER).unwrap()),
        AuditTarget::new(target_type, SPEC).unwrap(),
        EntityVersion::INITIAL,
        policy_version.map(|value| PolicyVersion::new(value).unwrap()),
    )
}

/// The GraphQL version of every answer, active.
pub(crate) fn active_graphql() -> GraphQlSpecSummary {
    let mut active = graphql_summary();
    active.spec.status = SpecStatus::Active;
    active.spec.activated_at = Some(SystemTime::UNIX_EPOCH);
    active
}

/// The `OpenAPI` version of every answer, active.
pub(crate) fn active_openapi() -> OpenApiSpecSummary {
    let mut active = openapi_summary();
    active.spec.status = SpecStatus::Active;
    active.spec.activated_at = Some(SystemTime::UNIX_EPOCH);
    active
}

/// What the doubles answer.
pub(crate) struct Answers {
    /// The answer of the GraphQL version query.
    pub graphql: Result<Option<GraphQlSpecSummary>, Refusal>,
    /// The answer of the `OpenAPI` version query.
    pub openapi: Result<Option<OpenApiSpecSummary>, Refusal>,
    /// The receipt that the idempotent-replay query finds, when it finds one.
    pub replay: Option<ChangeReceipt>,
    /// The answer of both retirement commands.
    pub command: Result<(), Refusal>,
    /// The type of the target that the receipt of the change names.
    pub target_type: &'static str,
    /// The policy version the receipt of the change holds.
    pub policy_version: Option<i64>,
}

impl Default for Answers {
    fn default() -> Self {
        Self {
            graphql: Ok(Some(active_graphql())),
            openapi: Ok(Some(active_openapi())),
            replay: None,
            command: Ok(()),
            target_type: "graphql_spec",
            policy_version: Some(7),
        }
    }
}

/// The values a double recorded.
pub(crate) type Log<T> = Arc<Mutex<Vec<T>>>;

/// The commands that were dispatched.
#[derive(Debug, Default)]
pub(crate) struct Dispatched {
    /// The GraphQL retirements.
    pub graphql: Log<RetireGraphQlSpecCommand>,
    /// The `OpenAPI` retirements.
    pub openapi: Log<RetireOpenApiSpecCommand>,
}

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
pub(crate) fn scenario(answers: Answers) -> (IamState, Dispatched) {
    let dispatched = Dispatched::default();
    let graphql_sink = Arc::clone(&dispatched.graphql);
    let openapi_sink = Arc::clone(&dispatched.openapi);
    let Answers {
        graphql,
        openapi,
        replay,
        command,
        target_type,
        policy_version,
    } = answers;
    let openapi_command = command;
    let command_bus: Arc<dyn CommandBus> = Arc::new(
        FakeCommandBus::handling(move |sent: RetireGraphQlSpecCommand| {
            push(&graphql_sink, sent);
            command.map_err(|refusal| refusal())
        })
        .and_handling(move |sent: RetireOpenApiSpecCommand| {
            push(&openapi_sink, sent);
            openapi_command.map_err(|refusal| refusal())
        }),
    );
    let query_bus: Arc<dyn QueryBus> = Arc::new(
        FakeQueryBus::answering(move |_query: GetGraphQlSpecQuery| {
            graphql.clone().map_err(|refusal| refusal())
        })
        .and_answering(move |_query: GetOpenApiSpecQuery| {
            openapi.clone().map_err(|refusal| refusal())
        })
        .and_answering(move |_query: GetIdempotentReplayQuery| Ok(replay.clone()))
        .and_answering(move |_query: GetChangeReceiptQuery| {
            Ok(receipt(target_type, policy_version))
        })
        .and_answering(|_query: GetPolicyEpochQuery| Ok(seeded_policy_epoch())),
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
