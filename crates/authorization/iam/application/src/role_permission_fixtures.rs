//! Values and doubles that the tests of the grants of a role of the REST and GraphQL adapters
//! share.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use iam_domain::{ChangeReceipt, EntityVersion, PermissionGrant, RoleGrant, RoleId, RoleParts};
use shared_domain::{CommandBus, QueryBus};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::request_digester::FakeRequestDigester;

use crate::command::set_role_permissions::SetRolePermissionsCommand;
use crate::error::IamError;
use crate::fixtures::{ROLE, receipt_at, role};
use crate::http::IamState;
use crate::query::get_change_receipt::GetChangeReceiptQuery;
use crate::query::get_idempotent_replay::GetIdempotentReplayQuery;
use crate::query::get_role::GetRoleQuery;
use crate::query::get_role_permissions::{GetRolePermissionsQuery, RolePermissions};

/// A bus error that a test builds when it needs it.
pub(crate) type Refusal = fn() -> IamError;

/// The grants that every answer lists: an active exact key and an inactive one.
pub(crate) fn grants() -> Vec<RoleGrant> {
    vec![
        RoleGrant {
            grant: PermissionGrant::parse("gql:billing:*").unwrap(),
            active: true,
        },
        RoleGrant {
            grant: PermissionGrant::parse("rest:billing:GET /invoices").unwrap(),
            active: false,
        },
    ]
}

/// The grants of the role at `version`.
pub(crate) fn permissions(version: i64) -> RolePermissions {
    RolePermissions {
        id: RoleId::parse(ROLE).unwrap(),
        version: EntityVersion::new(version).unwrap(),
        grants: grants(),
    }
}

/// What the doubles answer.
pub(crate) struct Answers {
    /// The answer of the idempotent-replay query.
    pub replay: Result<Option<ChangeReceipt>, Refusal>,
    /// The answer of the change-receipt query.
    pub receipt: ChangeReceipt,
    /// The answer of the grants query.
    pub permissions: Result<Option<RolePermissions>, Refusal>,
    /// The answer of the role query.
    pub role: Result<Option<RoleParts>, Refusal>,
    /// The answer of the command.
    pub command: Result<(), Refusal>,
}

impl Default for Answers {
    fn default() -> Self {
        Self {
            replay: Ok(None),
            receipt: receipt_at(2, Some(9)),
            permissions: Ok(Some(permissions(2))),
            role: Ok(Some(role(2))),
            command: Ok(()),
        }
    }
}

/// A shared log of what a double was asked.
pub(crate) type Log<T> = Arc<Mutex<Vec<T>>>;

/// The values a double recorded, in order.
pub(crate) fn recorded<T: Clone>(log: &Log<T>) -> Vec<T> {
    log.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

/// The state over doubles, the two buses and what the command bus and the replay query were
/// asked.
pub(crate) type Scenario = (
    IamState,
    Arc<FakeCommandBus>,
    Arc<FakeQueryBus>,
    Log<SetRolePermissionsCommand>,
    Log<GetIdempotentReplayQuery>,
);

/// The scenario over doubles that answer as `answers` say.
pub(crate) fn scenario(answers: Answers) -> Scenario {
    let sent: Log<SetRolePermissionsCommand> = Arc::default();
    let replays: Log<GetIdempotentReplayQuery> = Arc::default();
    let Answers {
        replay,
        receipt,
        permissions,
        role,
        command,
    } = answers;
    let command_log = Arc::clone(&sent);
    let commands = Arc::new(FakeCommandBus::handling(
        move |sent_command: SetRolePermissionsCommand| {
            command_log
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(sent_command);
            command.map_err(|refusal| refusal())
        },
    ));
    let replay_log = Arc::clone(&replays);
    let queries = Arc::new(
        FakeQueryBus::answering(move |query: GetIdempotentReplayQuery| {
            replay_log
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(query);
            replay.clone().map_err(|refusal| refusal())
        })
        .and_answering(move |_query: GetChangeReceiptQuery| Ok(receipt.clone()))
        .and_answering(move |_query: GetRolePermissionsQuery| {
            permissions.clone().map_err(|refusal| refusal())
        })
        .and_answering(move |_query: GetRoleQuery| role.clone().map_err(|refusal| refusal())),
    );
    let command_bus: Arc<dyn CommandBus> = Arc::<FakeCommandBus>::clone(&commands);
    let query_bus: Arc<dyn QueryBus> = Arc::<FakeQueryBus>::clone(&queries);
    let state = IamState {
        command_bus,
        query_bus,
        uuid_generator: Arc::new(SequenceUuidGenerator::starting_at(1)),
        clock: Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        request_digester: Arc::new(FakeRequestDigester),
    };
    (state, commands, queries, sent, replays)
}
