//! Values and doubles that the tests of the assignment operations of the REST and GraphQL
//! adapters share.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AssignmentScope, AuditTarget, ChangeId, ChangeReceipt, EntityVersion, PolicyVersion,
    RoleId, RoleName, SubjectRef, UserRoleId, UserRoleParts,
};
use shared_domain::{CommandBus, QueryBus, Uuid};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::request_digester::FakeRequestDigester;

use crate::command::assign_user_role::AssignUserRoleCommand;
use crate::fixtures::{ROLE, Refusal, USER};
use crate::http::IamState;
use crate::query::get_change_receipt::GetChangeReceiptQuery;
use crate::query::get_idempotent_replay::GetIdempotentReplayQuery;
use crate::query::get_user_role::{GetUserRoleQuery, UserRoleView};
use crate::query::list_user_roles::{ListUserRolesQuery, UserRolePage};

/// The assignment that every answer names.
pub(crate) const USER_ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890d0";
/// The user that receives the role.
pub(crate) const SUBJECT: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890d1";
/// The project of a project scope.
pub(crate) const PROJECT: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890d2";
/// The change that every receipt names.
const CHANGE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890d3";

/// A global assignment of the role Billing to a user at `version`, without an expiry.
pub(crate) fn user_role(version: i64) -> UserRoleView {
    UserRoleView {
        user_role: UserRoleParts {
            id: UserRoleId::parse(USER_ROLE).unwrap(),
            subject: SubjectRef::user(Uuid::parse(SUBJECT).unwrap()),
            role_id: RoleId::parse(ROLE).unwrap(),
            scope: AssignmentScope::Global,
            expires_at: None,
            version: EntityVersion::new(version).unwrap(),
            created_by: ActorRef::User(Uuid::parse(USER).unwrap()),
            created_at: SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_hours(500_000))
                .unwrap(),
            updated_at: SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_mins(30_000_001))
                .unwrap(),
            revoked_at: None,
        },
        role_name: Some(RoleName::new("Billing".to_owned()).unwrap()),
    }
}

/// The receipt of the assignment at version 1.
pub(crate) fn receipt(policy_version: Option<i64>) -> ChangeReceipt {
    ChangeReceipt::new(
        ChangeId::parse(CHANGE).unwrap(),
        ActorRef::User(Uuid::parse(USER).unwrap()),
        AuditTarget::new("user_role", USER_ROLE).unwrap(),
        EntityVersion::INITIAL,
        policy_version.map(|value| PolicyVersion::new(value).unwrap()),
    )
}

/// What the doubles answer.
pub(crate) struct Answers {
    /// The answer of the idempotent-replay query.
    pub replay: Result<Option<ChangeReceipt>, Refusal>,
    /// The answer of the change-receipt query.
    pub receipt: ChangeReceipt,
    /// The answer of the assignment query.
    pub user_role: Result<Option<UserRoleView>, Refusal>,
    /// The answer of the assignment-list query.
    pub page: Result<UserRolePage, Refusal>,
    /// The answer of the assign command.
    pub command: Result<(), Refusal>,
}

impl Default for Answers {
    fn default() -> Self {
        Self {
            replay: Ok(None),
            receipt: receipt(Some(1)),
            user_role: Ok(Some(user_role(1))),
            page: Ok(UserRolePage {
                user_roles: Vec::new(),
                next_after: None,
            }),
            command: Ok(()),
        }
    }
}

/// What the doubles were asked.
#[derive(Debug, Default)]
pub(crate) struct Asked {
    /// The assign commands that were dispatched.
    pub commands: Arc<Mutex<Vec<AssignUserRoleCommand>>>,
    /// The assignment queries.
    pub user_roles: Arc<Mutex<Vec<UserRoleId>>>,
    /// The assignment-list queries.
    pub lists: Arc<Mutex<Vec<ListUserRolesQuery>>>,
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
    let commands = Arc::new(command_bus(answers.command, &asked));
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

fn command_bus(answer: Result<(), Refusal>, asked: &Asked) -> FakeCommandBus {
    let log = Arc::clone(&asked.commands);
    FakeCommandBus::handling(move |command: AssignUserRoleCommand| {
        record(&log, command);
        answer.map_err(|refusal| refusal())
    })
}

fn query_bus(answers: Answers, asked: &Asked) -> FakeQueryBus {
    let Answers {
        replay,
        receipt,
        user_role,
        page,
        ..
    } = answers;
    let replays = Arc::clone(&asked.replays);
    let user_roles = Arc::clone(&asked.user_roles);
    let lists = Arc::clone(&asked.lists);
    FakeQueryBus::answering(move |query: GetIdempotentReplayQuery| {
        record(&replays, query);
        replay.clone().map_err(|refusal| refusal())
    })
    .and_answering(move |_query: GetChangeReceiptQuery| Ok(receipt.clone()))
    .and_answering(move |query: GetUserRoleQuery| {
        record(&user_roles, query.id);
        user_role.clone().map_err(|refusal| refusal())
    })
    .and_answering(move |query: ListUserRolesQuery| {
        record(&lists, query);
        page.clone().map_err(|refusal| refusal())
    })
}
