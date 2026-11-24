//! Values and doubles that the tests of the security audit reads share: the stored records and a
//! query bus that answers the two reads from them.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AuditAction, AuditHash, AuditOutcome, AuditReason, AuditSummary, AuditTarget,
    PolicyVersion, SecurityAuditEvent, SecurityAuditEventId, SecurityAuditEventParts,
    StoredSecurityAuditEvent,
};
use shared_domain::{CommandBus, QueryBus, Uuid};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::request_digester::FakeRequestDigester;

use crate::error::IamError;
use crate::fixtures::USER;
use crate::http::IamState;
use crate::query::get_security_audit_event::GetSecurityAuditEventQuery;
use crate::query::get_security_audit_events::{
    GetSecurityAuditEventsQuery, SecurityAuditEventPage,
};

/// The identifier of the committed record, the first of the chain.
pub(crate) const COMMITTED: &str = "00000000-0000-0000-0000-000000000001";

/// The identifier of the rejected record, the second of the chain.
pub(crate) const REJECTED: &str = "00000000-0000-0000-0000-000000000002";

/// An identifier no record has.
pub(crate) const UNKNOWN: &str = "00000000-0000-0000-0000-0000000000ff";

/// The identifier that ends in `n`.
pub(crate) fn uuid(n: u64) -> Uuid {
    Uuid::parse(&format!("00000000-0000-0000-0000-{n:012x}")).unwrap()
}

/// The user that acts in the records and asks in the queries.
pub(crate) fn actor() -> ActorRef {
    ActorRef::User(Uuid::parse(USER).unwrap())
}

/// The instant that the records of the fixtures happened at, `n` seconds after a fixed start.
pub(crate) fn at(n: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .and_then(|start| start.checked_add(Duration::from_secs(n)))
        .unwrap()
}

/// A hash whose last byte is `n`.
fn hash(n: u8) -> AuditHash {
    let mut bytes = [0; AuditHash::LENGTH];
    if let Some(last) = bytes.last_mut() {
        *last = n;
    }
    AuditHash::new(&bytes).unwrap()
}

/// The record at sequence number `seq` with the identifier that ends in `seq`: a committed
/// `role.update` of a role with before and after summaries and a policy version, or a rejected
/// `role.create` with a reason.
pub(crate) fn record(seq: u8, outcome: AuditOutcome) -> StoredSecurityAuditEvent {
    let committed = outcome == AuditOutcome::Committed;
    let event = SecurityAuditEvent::record(SecurityAuditEventParts {
        id: SecurityAuditEventId::from_uuid(uuid(u64::from(seq))),
        occurred_at: at(u64::from(seq)),
        actor: actor(),
        caller_service: None,
        action: AuditAction::new(if committed {
            "role.update"
        } else {
            "role.create"
        })
        .unwrap(),
        target: AuditTarget::new("role", "r-1").unwrap(),
        scope: None,
        before: committed.then(|| AuditSummary::new("name=readers").unwrap()),
        after: committed.then(|| AuditSummary::new("name=writers").unwrap()),
        idempotency_key: None,
        outcome,
        reason: (!committed).then(|| AuditReason::new("forbidden").unwrap()),
        policy_version: committed.then(|| PolicyVersion::new(7).unwrap()),
        request_id: None,
    })
    .unwrap();
    StoredSecurityAuditEvent::new(
        i64::from(seq),
        event,
        hash(seq.saturating_sub(1)),
        hash(seq),
    )
    .unwrap()
}

/// The two stored records: a committed one and a rejected one, oldest first.
pub(crate) fn stored() -> Vec<StoredSecurityAuditEvent> {
    vec![
        record(1, AuditOutcome::Committed),
        record(2, AuditOutcome::Rejected),
    ]
}

/// The queries the doubles were asked, oldest first.
#[derive(Debug, Default)]
pub(crate) struct Recorded {
    pub(crate) gets: Vec<GetSecurityAuditEventQuery>,
    pub(crate) lists: Vec<GetSecurityAuditEventsQuery>,
}

/// The recorded queries, shared with the closures of the bus.
pub(crate) type Asked = Arc<Mutex<Recorded>>;

/// The state over a query bus that reads `records` and records the queries; the list answers the
/// newest records first and ignores the filter, which the handler's own tests cover.
///
/// `failure` makes both reads fail with it.
pub(crate) fn scenario(
    records: Vec<StoredSecurityAuditEvent>,
    failure: Option<fn() -> IamError>,
) -> (IamState, Asked) {
    let asked: Asked = Arc::default();
    let get_log = Arc::clone(&asked);
    let list_log = Arc::clone(&asked);
    let for_get = records.clone();
    let queries = Arc::new(
        FakeQueryBus::answering(move |query: GetSecurityAuditEventQuery| {
            let id = query.id;
            get_log
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .gets
                .push(query);
            failure.map_or_else(
                || {
                    Ok(for_get
                        .iter()
                        .find(|stored| stored.event().parts().id == id)
                        .cloned())
                },
                |refuse| Err(refuse()),
            )
        })
        .and_answering(move |query: GetSecurityAuditEventsQuery| {
            let before = query.before_seq;
            let limit = query.limit;
            list_log
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .lists
                .push(query);
            failure.map_or_else(
                || Ok(page_of(&records, before, limit)),
                |refuse| Err(refuse()),
            )
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

/// The page of `records` that a search with the cursor `before` and the page size `limit` asks
/// for.
fn page_of(
    records: &[StoredSecurityAuditEvent],
    before: Option<i64>,
    limit: u32,
) -> SecurityAuditEventPage {
    let size = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut events: Vec<_> = records
        .iter()
        .rev()
        .filter(|stored| before.is_none_or(|seq| stored.seq() < seq))
        .cloned()
        .collect();
    let next_before = (events.len() > size)
        .then(|| {
            events
                .get(size.saturating_sub(1))
                .map(StoredSecurityAuditEvent::seq)
        })
        .flatten();
    events.truncate(size);
    SecurityAuditEventPage {
        events,
        next_before,
    }
}

/// How many queries of both kinds were asked.
pub(crate) fn asked_count(asked: &Asked) -> usize {
    let recorded = asked.lock().unwrap_or_else(PoisonError::into_inner);
    recorded.gets.len().saturating_add(recorded.lists.len())
}
