//! Values and doubles that the tests of the revocation reads share: the stored revocations and cut-offs
//! and a query bus that answers the four reads from them.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, GlobalTokenCutoff, RevocationSource, SessionId, SessionRevocation,
    SessionRevocationId, SystemComponent, UserTokenCutoff,
};
use shared_domain::{CommandBus, QueryBus, Uuid};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::request_digester::FakeRequestDigester;

use crate::error::IamError;
use crate::fixtures::USER;
use crate::http::IamState;
use crate::query::get_global_token_cutoff::GetGlobalTokenCutoffQuery;
use crate::query::get_session_revocation::GetSessionRevocationQuery;
use crate::query::get_user_token_cutoff::{GetUserTokenCutoffQuery, UserTokenCutoffView};
use crate::query::list_session_revocations::{ListSessionRevocationsQuery, SessionRevocationPage};

/// The identifier of the operator revocation, the older one.
pub(crate) const OPERATOR_REVOCATION: &str = "00000000-0000-0000-0000-000000000001";

/// The identifier of the User service revocation, the newer one.
pub(crate) const USER_SERVICE_REVOCATION: &str = "00000000-0000-0000-0000-000000000002";

/// An identifier no revocation has.
pub(crate) const UNKNOWN: &str = "00000000-0000-0000-0000-0000000000ff";

/// A user that has no cut-off.
pub(crate) const OTHER_USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ff";

/// The identifier that ends in `n`.
pub(crate) fn uuid(n: u64) -> Uuid {
    Uuid::parse(&format!("00000000-0000-0000-0000-{n:012x}")).unwrap()
}

/// The user of the revocations and the cut-off.
pub(crate) fn user() -> Uuid {
    Uuid::parse(USER).unwrap()
}

/// The operator that revoked.
pub(crate) fn operator() -> ActorRef {
    ActorRef::User(Uuid::parse(USER).unwrap())
}

/// The instant `n` seconds after a fixed start.
pub(crate) fn at(n: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .and_then(|start| start.checked_add(Duration::from_secs(n)))
        .unwrap()
}

/// The revocation with the identifier that ends in `n`, recorded `n * 10` seconds after the start;
/// an odd `n` is an operator revocation, an even one a User service revocation.
pub(crate) fn revocation(n: u64) -> SessionRevocation {
    let operator_made = n % 2 == 1;
    SessionRevocation {
        id: SessionRevocationId::from_uuid(uuid(n)),
        session: SessionId::new(&format!("session-{n}")).unwrap(),
        user: user(),
        source: if operator_made {
            RevocationSource::Operator
        } else {
            RevocationSource::UserService
        },
        revoked_by: if operator_made {
            operator()
        } else {
            ActorRef::System(SystemComponent::UserService)
        },
        revoked_at: at(n.saturating_mul(10)),
        prune_after: at(n.saturating_mul(10).saturating_add(1_000)),
    }
}

/// The two revocations, oldest first.
pub(crate) fn revocations() -> Vec<SessionRevocation> {
    vec![revocation(1), revocation(2)]
}

/// The cut-off of `user()` from `source`.
pub(crate) fn user_cutoff(source: RevocationSource) -> UserTokenCutoff {
    UserTokenCutoff {
        user: user(),
        tokens_valid_after: at(300),
        source,
        updated_at: at(299),
        prune_after: at(5_000),
    }
}

/// The view of the operator cut-off with its actor.
pub(crate) fn user_cutoff_view() -> UserTokenCutoffView {
    UserTokenCutoffView {
        cutoff: user_cutoff(RevocationSource::Operator),
        actor: Some(operator()),
    }
}

/// The global cut-off that the operator set.
pub(crate) fn global_cutoff() -> GlobalTokenCutoff {
    GlobalTokenCutoff {
        tokens_valid_after: at(400),
        set_by: operator(),
        set_at: at(399),
    }
}

/// What the doubles hold.
#[derive(Debug, Clone, Default)]
pub(crate) struct Stored {
    pub(crate) revocations: Vec<SessionRevocation>,
    pub(crate) user_cutoff: Option<UserTokenCutoffView>,
    pub(crate) global_cutoff: Option<GlobalTokenCutoff>,
}

/// The data of the usual scenario: both revocations and both cut-offs.
pub(crate) fn stored() -> Stored {
    Stored {
        revocations: revocations(),
        user_cutoff: Some(user_cutoff_view()),
        global_cutoff: Some(global_cutoff()),
    }
}

/// The queries the doubles were asked, oldest first.
#[derive(Debug, Default)]
pub(crate) struct Recorded {
    pub(crate) gets: Vec<GetSessionRevocationQuery>,
    pub(crate) lists: Vec<ListSessionRevocationsQuery>,
    pub(crate) users: Vec<GetUserTokenCutoffQuery>,
    pub(crate) globals: usize,
}

/// The recorded queries, shared with the closures of the bus.
pub(crate) type Asked = Arc<Mutex<Recorded>>;

/// The state over a query bus that reads `stored` and records the queries; the list answers the
/// newest revocations first after its cursor and ignores the filters, which the handler's own
/// tests cover.
///
/// `failure` makes all four reads fail with it.
pub(crate) fn scenario(stored: Stored, failure: Option<fn() -> IamError>) -> (IamState, Asked) {
    let asked: Asked = Arc::default();
    let (get_log, list_log, user_log, global_log) = (
        Arc::clone(&asked),
        Arc::clone(&asked),
        Arc::clone(&asked),
        Arc::clone(&asked),
    );
    let for_get = stored.revocations.clone();
    let for_list = stored.revocations;
    let user_view = stored.user_cutoff;
    let global = stored.global_cutoff;
    let queries = Arc::new(
        FakeQueryBus::answering(move |query: GetSessionRevocationQuery| {
            let id = query.id;
            lock(&get_log).gets.push(query);
            failure.map_or_else(
                || Ok(for_get.iter().find(|stored| stored.id == id).cloned()),
                |refuse| Err(refuse()),
            )
        })
        .and_answering(move |query: ListSessionRevocationsQuery| {
            let (after, limit) = (query.after, query.limit);
            lock(&list_log).lists.push(query);
            failure.map_or_else(
                || Ok(page_of(&for_list, after, limit)),
                |refuse| Err(refuse()),
            )
        })
        .and_answering(move |query: GetUserTokenCutoffQuery| {
            let user = query.user;
            lock(&user_log).users.push(query);
            failure.map_or_else(
                || Ok(user_view.clone().filter(|view| view.cutoff.user == user)),
                |refuse| Err(refuse()),
            )
        })
        .and_answering(move |_query: GetGlobalTokenCutoffQuery| {
            {
                let mut log = lock(&global_log);
                log.globals = log.globals.saturating_add(1);
            }
            failure.map_or_else(|| Ok(global.clone()), |refuse| Err(refuse()))
        }),
    );
    let commands = Arc::new(FakeCommandBus::unregistered());
    let command_bus: Arc<dyn CommandBus> = commands;
    let query_bus: Arc<dyn QueryBus> = queries;
    let state = IamState {
        command_bus,
        query_bus,
        uuid_generator: Arc::new(SequenceUuidGenerator::starting_at(1)),
        clock: Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        request_digester: Arc::new(FakeRequestDigester),
    };
    (state, asked)
}

fn lock(asked: &Asked) -> std::sync::MutexGuard<'_, Recorded> {
    asked.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The page of `records` that a search with the cursor `after` and the page size `limit` asks for.
fn page_of(
    records: &[SessionRevocation],
    after: Option<SessionRevocationId>,
    limit: u32,
) -> SessionRevocationPage {
    let size = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut newest_first: Vec<SessionRevocation> = records.iter().rev().cloned().collect();
    if let Some(cursor) = after {
        let position = newest_first
            .iter()
            .position(|stored| stored.id == cursor)
            .map_or(0, |index| index.saturating_add(1));
        newest_first.drain(..position);
    }
    let next_after = (newest_first.len() > size)
        .then(|| newest_first.get(size.saturating_sub(1)).map(|last| last.id))
        .flatten();
    newest_first.truncate(size);
    SessionRevocationPage {
        revocations: newest_first,
        next_after,
    }
}

/// How many queries of all kinds were asked.
pub(crate) fn asked_count(asked: &Asked) -> usize {
    let recorded = lock(asked);
    recorded
        .gets
        .len()
        .saturating_add(recorded.lists.len())
        .saturating_add(recorded.users.len())
        .saturating_add(recorded.globals)
}
