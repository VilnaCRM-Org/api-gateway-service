//! Values and doubles that the tests of the bulk operation reads of the REST and GraphQL adapters
//! share.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, BulkKind, BulkOperationId, BulkOperationParts, BulkStatus, PolicyVersion,
};
use shared_domain::{CommandBus, QueryBus, Uuid};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::request_digester::FakeRequestDigester;

use crate::error::IamError;
use crate::http::IamState;
use crate::query::get_bulk_operation::GetBulkOperationQuery;
use crate::query::list_bulk_operations::{BulkOperationPage, ListBulkOperationsQuery};

/// The requester of every operation of the fixtures.
pub(crate) const REQUESTER: &str = "user:7f0cdd0e-6c1a-4a3b-9f7e-0b8e8f5f5f01";

/// The identifier of the running operation.
pub(crate) const RUNNING: &str = "00000000-0000-0000-0000-000000000001";

/// The identifier of the completed operation.
pub(crate) const COMPLETED: &str = "00000000-0000-0000-0000-000000000002";

/// An identifier no operation has.
pub(crate) const UNKNOWN: &str = "00000000-0000-0000-0000-0000000000ff";

/// The identifier that ends in `n`, as the constants of the fixtures spell them.
pub(crate) fn uuid(n: u64) -> Uuid {
    Uuid::parse(&format!("00000000-0000-0000-0000-{n:012x}")).unwrap()
}

/// The queries the doubles were asked, oldest first.
#[derive(Debug, Default)]
pub(crate) struct Recorded {
    pub(crate) gets: Vec<GetBulkOperationQuery>,
    pub(crate) lists: Vec<ListBulkOperationsQuery>,
}

/// The recorded queries, shared with the closures of the bus.
pub(crate) type Asked = Arc<Mutex<Recorded>>;

/// A bulk operation of 2,500 records in `status` that applied `applied` of them.
pub(crate) fn operation(id: u64, status: BulkStatus, applied: u64) -> BulkOperationParts {
    let at = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap();
    let started = applied > 0;
    BulkOperationParts {
        id: BulkOperationId::from_uuid(uuid(id)),
        kind: BulkKind::RoleDeletion,
        status,
        total_records: 2_500,
        applied_records: applied,
        first_version: started.then(|| PolicyVersion::new(4).unwrap()),
        last_version: started.then(|| PolicyVersion::new(5).unwrap()),
        requester: ActorRef::parse(REQUESTER).unwrap(),
        error: None,
        created_at: at,
        updated_at: at,
    }
}

/// The two stored operations: a running one and a completed one.
pub(crate) fn stored() -> Vec<BulkOperationParts> {
    vec![
        operation(1, BulkStatus::Running, 1_000),
        operation(2, BulkStatus::Completed, 2_500),
    ]
}

/// The state over a query bus that reads `operations` and records the queries.
///
/// `failure` makes both reads fail with it.
pub(crate) fn scenario(
    operations: Vec<BulkOperationParts>,
    failure: Option<fn() -> IamError>,
) -> (IamState, Asked) {
    let asked: Asked = Arc::default();
    let get_log = Arc::clone(&asked);
    let list_log = Arc::clone(&asked);
    let for_get = operations.clone();
    let queries = Arc::new(
        FakeQueryBus::answering(move |query: GetBulkOperationQuery| {
            get_log
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .gets
                .push(query);
            failure.map_or_else(
                || Ok(for_get.iter().find(|stored| stored.id == query.id).cloned()),
                |refuse| Err(refuse()),
            )
        })
        .and_answering(move |query: ListBulkOperationsQuery| {
            list_log
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .lists
                .push(query);
            failure.map_or_else(|| Ok(page_of(&operations, &query)), |refuse| Err(refuse()))
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

/// The page of `operations` that `query` asks for.
fn page_of(
    operations: &[BulkOperationParts],
    query: &ListBulkOperationsQuery,
) -> BulkOperationPage {
    let limit = usize::try_from(query.limit).unwrap_or(usize::MAX);
    let mut page: Vec<_> = operations
        .iter()
        .filter(|stored| query.after.is_none_or(|after| stored.id > after))
        .cloned()
        .collect();
    let next_after = (page.len() > limit)
        .then(|| page.get(limit.saturating_sub(1)).map(|last| last.id))
        .flatten();
    page.truncate(limit);
    BulkOperationPage {
        operations: page,
        next_after,
    }
}

/// How many queries of both kinds were asked.
pub(crate) fn asked_count(asked: &Asked) -> usize {
    let recorded = asked.lock().unwrap_or_else(PoisonError::into_inner);
    recorded.gets.len().saturating_add(recorded.lists.len())
}
