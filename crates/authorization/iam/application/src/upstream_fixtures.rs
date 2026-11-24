//! Values and doubles that the tests of the upstream operations share: the commands, the queries
//! and the REST and GraphQL adapters.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AuditTarget, ChangeId, ChangeReceipt, EntityVersion, PolicyVersion, UpstreamFields,
    UpstreamId, UpstreamParts, UpstreamProtocol, UpstreamSettingsDraft,
};
use shared_domain::{CommandBus, QueryBus, Uuid};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::request_digester::FakeRequestDigester;

use crate::command::create_upstream::CreateUpstreamCommand;
use crate::command::delete_upstream::DeleteUpstreamCommand;
use crate::command::update_upstream::UpdateUpstreamCommand;
use crate::error::IamError;
use crate::fixtures::USER;
use crate::http::IamState;
use crate::query::get_change_receipt::GetChangeReceiptQuery;
use crate::query::get_idempotent_replay::GetIdempotentReplayQuery;
use crate::query::get_upstream::GetUpstreamQuery;
use crate::query::list_upstreams::{ListUpstreamsQuery, UpstreamPage};

/// The upstream that every answer names.
pub(crate) const UPSTREAM: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890cf";
/// The change that every receipt names.
const CHANGE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890d0";

/// A bus error that a test builds when it needs it.
pub(crate) type Refusal = fn() -> IamError;

/// The instant that the fixtures use as the time of a change.
pub(crate) fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

/// The user that acts.
pub(crate) fn actor() -> ActorRef {
    ActorRef::User(Uuid::parse(USER).unwrap())
}

/// The id of the upstream that every answer names.
pub(crate) fn upstream_id() -> UpstreamId {
    UpstreamId::parse(UPSTREAM).unwrap()
}

/// The id of the change that every receipt names.
pub(crate) fn change_id() -> ChangeId {
    ChangeId::parse(CHANGE).unwrap()
}

/// A valid draft of the settings of an upstream that serves `catalog_service`.
pub(crate) fn draft(catalog_service: &str) -> UpstreamSettingsDraft {
    UpstreamSettingsDraft {
        namespace: "platform".to_owned(),
        service_name: "core-service".to_owned(),
        catalog_service: catalog_service.to_owned(),
        port: 8080,
        protocol: UpstreamProtocol::H2c,
        forward_credentials: false,
        connect_timeout_ms: 250,
        response_timeout_ms: 10_000,
        concurrency_limit: 256,
        retry_budget_percent: 10,
        outlier_threshold: 5,
    }
}

/// The stored state of the upstream `name` that serves `catalog_service`, at `version`.
pub(crate) fn upstream_named(
    id: UpstreamId,
    name: &str,
    catalog_service: &str,
    version: i64,
) -> UpstreamParts {
    let (name, settings) = UpstreamFields::new(name, &draft(catalog_service))
        .unwrap()
        .into_parts();
    UpstreamParts {
        id,
        name,
        settings,
        system: false,
        version: EntityVersion::new(version).unwrap(),
        created_at: at(),
        updated_at: at().checked_add(Duration::from_mins(5)).unwrap(),
        deleted_at: None,
    }
}

/// The stored state of the upstream `core` of the service `core`, at `version`.
pub(crate) fn upstream(version: i64) -> UpstreamParts {
    upstream_named(upstream_id(), "core", "core", version)
}

/// The receipt of the creation of the upstream at version 1.
pub(crate) fn receipt(policy_version: Option<i64>) -> ChangeReceipt {
    receipt_at(1, policy_version)
}

/// The receipt of a change that left the upstream at `version`.
pub(crate) fn receipt_at(version: i64, policy_version: Option<i64>) -> ChangeReceipt {
    ChangeReceipt::new(
        change_id(),
        actor(),
        AuditTarget::new("upstream", UPSTREAM).unwrap(),
        EntityVersion::new(version).unwrap(),
        policy_version.map(|value| PolicyVersion::new(value).unwrap()),
    )
}

/// What the doubles answer.
pub(crate) struct Answers {
    /// The answer of the idempotent-replay query.
    pub replay: Result<Option<ChangeReceipt>, Refusal>,
    /// The answer of the change-receipt query.
    pub receipt: ChangeReceipt,
    /// The answer of the upstream query.
    pub upstream: Result<Option<UpstreamParts>, Refusal>,
    /// The answer of the upstream-list query.
    pub page: Result<UpstreamPage, Refusal>,
    /// The answer of the create command.
    pub command: Result<(), Refusal>,
    /// The answer of the update command.
    pub update: Result<(), Refusal>,
    /// The answer of the delete command.
    pub delete: Result<(), Refusal>,
}

impl Default for Answers {
    fn default() -> Self {
        Self {
            replay: Ok(None),
            receipt: receipt(None),
            upstream: Ok(Some(upstream(1))),
            page: Ok(UpstreamPage {
                upstreams: Vec::new(),
                next_after: None,
            }),
            command: Ok(()),
            update: Ok(()),
            delete: Ok(()),
        }
    }
}

/// A shared log of what a double was asked.
pub(crate) type Log<T> = Arc<Mutex<Vec<T>>>;

/// What the doubles were asked.
#[derive(Debug, Default)]
pub(crate) struct Asked {
    /// The create commands that were dispatched.
    pub commands: Log<CreateUpstreamCommand>,
    /// The update commands that were dispatched.
    pub updates: Log<UpdateUpstreamCommand>,
    /// The delete commands that were dispatched.
    pub deletions: Log<DeleteUpstreamCommand>,
    /// The upstream queries.
    pub upstreams: Log<UpstreamId>,
    /// The upstream-list queries.
    pub lists: Log<ListUpstreamsQuery>,
    /// The idempotent-replay queries.
    pub replays: Log<GetIdempotentReplayQuery>,
}

/// The values a double recorded, in order.
pub(crate) fn recorded<T: Clone>(log: &Log<T>) -> Vec<T> {
    log.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

fn record<T>(log: &Log<T>, value: T) {
    log.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(value);
}

/// The state over doubles that answer as `answers` say and record what they were asked, with the
/// two buses to read their asked names.
pub(crate) fn scenario(
    answers: Answers,
) -> (IamState, Arc<FakeCommandBus>, Arc<FakeQueryBus>, Asked) {
    let asked = Asked::default();
    let commands = Arc::new(command_bus(
        answers.command,
        answers.update,
        answers.delete,
        &asked,
    ));
    let queries = Arc::new(query_bus(answers, &asked));
    let command_bus: Arc<dyn CommandBus> = Arc::<FakeCommandBus>::clone(&commands);
    let query_bus: Arc<dyn QueryBus> = Arc::<FakeQueryBus>::clone(&queries);
    let state = IamState {
        command_bus,
        query_bus,
        uuid_generator: Arc::new(SequenceUuidGenerator::starting_at(1)),
        clock: Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        request_digester: Arc::new(FakeRequestDigester),
    };
    (state, commands, queries, asked)
}

fn command_bus(
    answer: Result<(), Refusal>,
    update: Result<(), Refusal>,
    delete: Result<(), Refusal>,
    asked: &Asked,
) -> FakeCommandBus {
    let log = Arc::clone(&asked.commands);
    let updates = Arc::clone(&asked.updates);
    let deletions = Arc::clone(&asked.deletions);
    FakeCommandBus::handling(move |command: CreateUpstreamCommand| {
        record(&log, command);
        answer.map_err(|refusal| refusal())
    })
    .and_handling(move |command: UpdateUpstreamCommand| {
        record(&updates, command);
        update.map_err(|refusal| refusal())
    })
    .and_handling(move |command: DeleteUpstreamCommand| {
        record(&deletions, command);
        delete.map_err(|refusal| refusal())
    })
}

fn query_bus(answers: Answers, asked: &Asked) -> FakeQueryBus {
    let Answers {
        replay,
        receipt,
        upstream,
        page,
        ..
    } = answers;
    let replays = Arc::clone(&asked.replays);
    let upstreams = Arc::clone(&asked.upstreams);
    let lists = Arc::clone(&asked.lists);
    FakeQueryBus::answering(move |query: GetIdempotentReplayQuery| {
        record(&replays, query);
        replay.clone().map_err(|refusal| refusal())
    })
    .and_answering(move |_query: GetChangeReceiptQuery| Ok(receipt.clone()))
    .and_answering(move |query: GetUpstreamQuery| {
        record(&upstreams, query.id);
        upstream.clone().map_err(|refusal| refusal())
    })
    .and_answering(move |query: ListUpstreamsQuery| {
        record(&lists, query);
        page.clone().map_err(|refusal| refusal())
    })
}
