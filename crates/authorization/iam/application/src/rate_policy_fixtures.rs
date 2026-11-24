//! Values and doubles that the tests of the rate-policy operations of the REST and GraphQL
//! adapters share.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AuditTarget, ChangeId, ChangeReceipt, EntityVersion, PolicyVersion, RateFallback,
    RateKeyKind, RatePolicyDraft, RatePolicyFields, RatePolicyId, RatePolicyParts,
};
use shared_domain::{CommandBus, QueryBus, Uuid};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::request_digester::FakeRequestDigester;

use crate::command::create_rate_policy::CreateRatePolicyCommand;
use crate::command::delete_rate_policy::DeleteRatePolicyCommand;
use crate::command::update_rate_policy::UpdateRatePolicyCommand;
use crate::fixtures::{Refusal, USER};
use crate::http::IamState;
use crate::query::get_change_receipt::GetChangeReceiptQuery;
use crate::query::get_idempotent_replay::GetIdempotentReplayQuery;
use crate::query::get_rate_policy::GetRatePolicyQuery;
use crate::query::list_rate_policies::{ListRatePoliciesQuery, RatePolicyPage};

/// The rate policy that every answer names.
pub(crate) const POLICY: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ae";
/// The change that every receipt names.
const CHANGE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890af";

/// A rate policy named `per-subject` that allows 100 requests a minute per subject and route with a
/// burst of 20, at `version`.
pub(crate) fn rate_policy(version: i64) -> RatePolicyParts {
    RatePolicyParts {
        id: RatePolicyId::parse(POLICY).unwrap(),
        fields: RatePolicyFields::new(RatePolicyDraft {
            name: "per-subject".to_owned(),
            key_kind: RateKeyKind::SubjectRoute,
            limit: 100,
            period_seconds: 60,
            burst: 20,
            fallback: RateFallback::Divided,
        })
        .unwrap(),
        version: EntityVersion::new(version).unwrap(),
        created_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_hours(500_000))
            .unwrap(),
        updated_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_mins(30_000_001))
            .unwrap(),
        deleted_at: None,
    }
}

/// The receipt of the creation of the rate policy at version 1.
pub(crate) fn receipt(policy_version: Option<i64>) -> ChangeReceipt {
    receipt_at(1, policy_version)
}

/// The receipt of a change that left the rate policy at `version`.
pub(crate) fn receipt_at(version: i64, policy_version: Option<i64>) -> ChangeReceipt {
    ChangeReceipt::new(
        ChangeId::parse(CHANGE).unwrap(),
        ActorRef::User(Uuid::parse(USER).unwrap()),
        AuditTarget::new("rate_policy", POLICY).unwrap(),
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
    /// The answer of the rate-policy query.
    pub rate_policy: Result<Option<RatePolicyParts>, Refusal>,
    /// The answer of the rate-policy list query.
    pub page: Result<RatePolicyPage, Refusal>,
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
            receipt: receipt(Some(1)),
            rate_policy: Ok(Some(rate_policy(1))),
            page: Ok(RatePolicyPage {
                rate_policies: Vec::new(),
                next_after: None,
            }),
            command: Ok(()),
            update: Ok(()),
            delete: Ok(()),
        }
    }
}

/// What the doubles were asked.
#[derive(Debug, Default)]
pub(crate) struct Asked {
    /// The create commands that were dispatched.
    pub commands: Arc<Mutex<Vec<CreateRatePolicyCommand>>>,
    /// The update commands that were dispatched.
    pub updates: Arc<Mutex<Vec<UpdateRatePolicyCommand>>>,
    /// The delete commands that were dispatched.
    pub deletions: Arc<Mutex<Vec<DeleteRatePolicyCommand>>>,
    /// The rate-policy queries.
    pub rate_policies: Arc<Mutex<Vec<RatePolicyId>>>,
    /// The rate-policy list queries.
    pub lists: Arc<Mutex<Vec<ListRatePoliciesQuery>>>,
    /// The idempotent-replay queries.
    pub replays: Arc<Mutex<Vec<GetIdempotentReplayQuery>>>,
}

fn record<T>(log: &Arc<Mutex<Vec<T>>>, value: T) {
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
        (answers.command, answers.update, answers.delete),
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

/// The answers of the create, update and delete commands, in that order.
type CommandAnswers = (
    Result<(), Refusal>,
    Result<(), Refusal>,
    Result<(), Refusal>,
);

fn command_bus(answers: CommandAnswers, asked: &Asked) -> FakeCommandBus {
    let (create, update, delete) = answers;
    let log = Arc::clone(&asked.commands);
    let updates = Arc::clone(&asked.updates);
    let deletions = Arc::clone(&asked.deletions);
    FakeCommandBus::handling(move |command: CreateRatePolicyCommand| {
        record(&log, command);
        create.map_err(|refusal| refusal())
    })
    .and_handling(move |command: UpdateRatePolicyCommand| {
        record(&updates, command);
        update.map_err(|refusal| refusal())
    })
    .and_handling(move |command: DeleteRatePolicyCommand| {
        record(&deletions, command);
        delete.map_err(|refusal| refusal())
    })
}

fn query_bus(answers: Answers, asked: &Asked) -> FakeQueryBus {
    let Answers {
        replay,
        receipt,
        rate_policy,
        page,
        ..
    } = answers;
    let replays = Arc::clone(&asked.replays);
    let policies = Arc::clone(&asked.rate_policies);
    let lists = Arc::clone(&asked.lists);
    FakeQueryBus::answering(move |query: GetIdempotentReplayQuery| {
        record(&replays, query);
        replay.clone().map_err(|refusal| refusal())
    })
    .and_answering(move |_query: GetChangeReceiptQuery| Ok(receipt.clone()))
    .and_answering(move |query: GetRatePolicyQuery| {
        record(&policies, query.id);
        rate_policy.clone().map_err(|refusal| refusal())
    })
    .and_answering(move |query: ListRatePoliciesQuery| {
        record(&lists, query);
        page.clone().map_err(|refusal| refusal())
    })
}
