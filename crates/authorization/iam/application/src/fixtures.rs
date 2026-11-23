//! Values and doubles that the tests of the role operations of the REST and GraphQL adapters share.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessToken, AccessTokenParts, ActorRef, AuditTarget, ChangeId, ChangeReceipt, EntityVersion,
    PermissionGrantSet, PolicyVersion, RoleDescription, RoleId, RoleKind, RoleName, RoleParts,
    SessionId, SubjectId, TokenId, TokenIdentity,
};
use shared_domain::{CommandBus, QueryBus, Uuid};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::request_digester::FakeRequestDigester;

use crate::command::create_role::CreateRoleCommand;
use crate::command::delete_role::DeleteRoleCommand;
use crate::command::update_role::UpdateRoleCommand;
use crate::error::IamError;
use crate::http::IamState;
use crate::principal::Principal;
use crate::query::get_change_receipt::GetChangeReceiptQuery;
use crate::query::get_idempotent_replay::GetIdempotentReplayQuery;
use crate::query::get_role::GetRoleQuery;
use crate::query::list_roles::{ListRolesQuery, RolePage};

/// The user that calls.
pub(crate) const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
/// The role that every answer names.
pub(crate) const ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890cd";
/// The change that every receipt names.
const CHANGE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ce";

/// A bus error that a test builds when it needs it.
pub(crate) type Refusal = fn() -> IamError;

/// The principal of a valid user token.
pub(crate) fn principal() -> Principal {
    Principal::from(TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(Uuid::parse(USER).unwrap()),
        session: Some(SessionId::new("session-1").unwrap()),
        token_id: TokenId::new("jti-1").unwrap(),
        roles: vec!["ROLE_USER".to_owned()],
        issued_at: SystemTime::UNIX_EPOCH,
        expires_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_mins(15))
            .unwrap(),
    })))
}

/// A custom role named Billing with a description and no grant, at `version`.
pub(crate) fn role(version: i64) -> RoleParts {
    RoleParts {
        id: RoleId::parse(ROLE).unwrap(),
        name: RoleName::new("Billing".to_owned()).unwrap(),
        description: Some(RoleDescription::new("Invoices".to_owned()).unwrap()),
        kind: RoleKind::Custom,
        grants: PermissionGrantSet::default(),
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

/// The receipt of the creation of the role at version 1.
pub(crate) fn receipt(policy_version: Option<i64>) -> ChangeReceipt {
    receipt_at(1, policy_version)
}

/// The receipt of a change that left the role at `version`.
pub(crate) fn receipt_at(version: i64, policy_version: Option<i64>) -> ChangeReceipt {
    ChangeReceipt::new(
        ChangeId::parse(CHANGE).unwrap(),
        ActorRef::User(Uuid::parse(USER).unwrap()),
        AuditTarget::new("role", ROLE).unwrap(),
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
    /// The answer of the role query.
    pub role: Result<Option<RoleParts>, Refusal>,
    /// The answer of the role-list query.
    pub page: Result<RolePage, Refusal>,
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
            role: Ok(Some(role(1))),
            page: Ok(RolePage {
                roles: Vec::new(),
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
    pub commands: Arc<Mutex<Vec<CreateRoleCommand>>>,
    /// The update commands that were dispatched.
    pub updates: Arc<Mutex<Vec<UpdateRoleCommand>>>,
    /// The delete commands that were dispatched.
    pub deletions: Arc<Mutex<Vec<DeleteRoleCommand>>>,
    /// The role queries.
    pub roles: Arc<Mutex<Vec<RoleId>>>,
    /// The role-list queries.
    pub lists: Arc<Mutex<Vec<ListRolesQuery>>>,
    /// The idempotent-replay queries.
    pub replays: Arc<Mutex<Vec<GetIdempotentReplayQuery>>>,
}

/// The values a double recorded, in order.
pub(crate) fn recorded<T: Clone>(log: &Arc<Mutex<Vec<T>>>) -> Vec<T> {
    log.lock().unwrap_or_else(PoisonError::into_inner).clone()
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
    FakeCommandBus::handling(move |command: CreateRoleCommand| {
        record(&log, command);
        answer.map_err(|refusal| refusal())
    })
    .and_handling(move |command: UpdateRoleCommand| {
        record(&updates, command);
        update.map_err(|refusal| refusal())
    })
    .and_handling(move |command: DeleteRoleCommand| {
        record(&deletions, command);
        delete.map_err(|refusal| refusal())
    })
}

fn query_bus(answers: Answers, asked: &Asked) -> FakeQueryBus {
    let Answers {
        replay,
        receipt,
        role,
        page,
        ..
    } = answers;
    let replays = Arc::clone(&asked.replays);
    let roles = Arc::clone(&asked.roles);
    let lists = Arc::clone(&asked.lists);
    FakeQueryBus::answering(move |query: GetIdempotentReplayQuery| {
        record(&replays, query);
        replay.clone().map_err(|refusal| refusal())
    })
    .and_answering(move |_query: GetChangeReceiptQuery| Ok(receipt.clone()))
    .and_answering(move |query: GetRoleQuery| {
        record(&roles, query.id);
        role.clone().map_err(|refusal| refusal())
    })
    .and_answering(move |query: ListRolesQuery| {
        record(&lists, query);
        page.clone().map_err(|refusal| refusal())
    })
}
