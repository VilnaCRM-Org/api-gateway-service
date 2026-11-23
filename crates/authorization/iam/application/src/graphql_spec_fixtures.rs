//! Values and doubles that the tests of the GraphQL specification operations of the REST and
//! GraphQL adapters share.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, ContentHash, CoordinateSet, GqlName, GraphQlCoordinate, GraphQlField,
    GraphQlSpecContent, GraphQlSpecParts, GraphQlTypeGraph, PermissionFlags, ServiceName, SpecDiff,
    SpecId, SpecStatus,
};
use shared_domain::{CommandBus, QueryBus, Uuid};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::request_digester::FakeRequestDigester;

use crate::command::load_graphql_spec::LoadGraphQlSpecCommand;
use crate::error::IamError;
use crate::fixtures::USER;
use crate::http::IamState;
use crate::query::find_graphql_spec::FindGraphQlSpecQuery;
use crate::query::get_graphql_spec::GetGraphQlSpecQuery;
use crate::query::get_graphql_spec_diff::{GetGraphQlSpecDiffQuery, GraphQlSpecView};
use crate::query::get_graphql_specs::{GetGraphQlSpecsQuery, GraphQlSpecPage, GraphQlSpecSummary};

/// The version that every answer names.
pub(crate) const SPEC: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";

/// A bus error that a test builds when it needs it.
pub(crate) type Refusal = fn() -> IamError;

/// What the doubles answer.
pub(crate) struct Answers {
    /// The version that already holds the SDL, when the answer to the lookup is one.
    pub existing: Result<Option<SpecId>, Refusal>,
    /// The answer of the version query.
    pub view: Result<Option<GraphQlSpecView>, Refusal>,
    /// The answer of the load command.
    pub command: Result<(), Refusal>,
}

impl Default for Answers {
    fn default() -> Self {
        Self {
            existing: Ok(None),
            view: Ok(Some(view())),
            command: Ok(()),
        }
    }
}

/// What the doubles were asked.
#[derive(Debug, Default)]
pub(crate) struct Asked {
    /// The load commands that were dispatched.
    pub commands: Arc<Mutex<Vec<LoadGraphQlSpecCommand>>>,
    /// The lookups by content hash.
    pub finds: Arc<Mutex<Vec<FindGraphQlSpecQuery>>>,
    /// The version queries.
    pub reads: Arc<Mutex<Vec<SpecId>>>,
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

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

/// A draft version of `billing` with the coordinate `Query.invoices` and its diff against nothing.
pub(crate) fn view() -> GraphQlSpecView {
    let coordinate = GraphQlCoordinate::parse("Query.invoices").unwrap();
    let graph = GraphQlTypeGraph::new(
        [(
            coordinate,
            GraphQlField {
                return_type: GqlName::parse("String").unwrap(),
                flags: PermissionFlags::NONE,
            },
        )],
        [],
    )
    .unwrap();
    let service = ServiceName::new("billing").unwrap();
    let spec = GraphQlSpecParts {
        id: SpecId::parse(SPEC).unwrap(),
        content: GraphQlSpecContent {
            service: service.clone(),
            content_hash: ContentHash::new(&[0xab; 32]).unwrap(),
            type_graph: graph.clone(),
        },
        status: SpecStatus::Draft,
        uploaded_by: ActorRef::User(Uuid::parse(USER).unwrap()),
        created_at: at(86_400),
        activated_at: None,
        retired_at: None,
    };
    GraphQlSpecView {
        coordinate_count: 1,
        diff: SpecDiff::compute(&service, &graph.coordinates(), &CoordinateSet::new(), &[]),
        spec,
    }
}

/// The state over doubles that answer as `answers` say and record what they were asked.
pub(crate) fn scenario(answers: Answers) -> (IamState, Asked) {
    let asked = Asked::default();
    let Answers {
        existing,
        view,
        command,
    } = answers;
    let commands = Arc::clone(&asked.commands);
    let command_bus: Arc<dyn CommandBus> = Arc::new(FakeCommandBus::handling(
        move |load: LoadGraphQlSpecCommand| {
            record(&commands, load);
            command.map_err(|refusal| refusal())
        },
    ));
    let finds = Arc::clone(&asked.finds);
    let reads = Arc::clone(&asked.reads);
    let query_bus: Arc<dyn QueryBus> = Arc::new(
        FakeQueryBus::answering(move |query: FindGraphQlSpecQuery| {
            record(&finds, query);
            existing.map_err(|refusal| refusal())
        })
        .and_answering(move |query: GetGraphQlSpecDiffQuery| {
            record(&reads, query.id);
            view.clone().map_err(|refusal| refusal())
        }),
    );
    let state = IamState {
        command_bus,
        query_bus,
        uuid_generator: Arc::new(SequenceUuidGenerator::starting_at(1)),
        clock: Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        request_digester: Arc::new(FakeRequestDigester),
    };
    (state, asked)
}

/// What the doubles of the read operations answer.
pub(crate) struct ReadAnswers {
    /// The answer of the list query.
    pub page: Result<GraphQlSpecPage, Refusal>,
    /// The answer of the query of one version.
    pub one: Result<Option<GraphQlSpecSummary>, Refusal>,
    /// The answer of the diff query.
    pub diff: Result<Option<GraphQlSpecView>, Refusal>,
}

impl Default for ReadAnswers {
    fn default() -> Self {
        Self {
            page: Ok(GraphQlSpecPage {
                specs: vec![summary()],
                next_after: Some(SpecId::parse(SPEC).unwrap()),
            }),
            one: Ok(Some(summary())),
            diff: Ok(Some(view())),
        }
    }
}

/// What the doubles of the read operations were asked.
#[derive(Debug, Default)]
pub(crate) struct ReadAsked {
    /// The list queries.
    pub pages: Arc<Mutex<Vec<GetGraphQlSpecsQuery>>>,
    /// The queries of one version.
    pub ones: Arc<Mutex<Vec<GetGraphQlSpecQuery>>>,
    /// The diff queries.
    pub diffs: Arc<Mutex<Vec<SpecId>>>,
}

/// The version of [`view`] without its diff and without an SDL.
pub(crate) fn summary() -> GraphQlSpecSummary {
    let view = view();
    GraphQlSpecSummary {
        spec: view.spec,
        coordinate_count: view.coordinate_count,
        sdl: None,
    }
}

/// The state over doubles that answer the read queries as `answers` say and record what they were
/// asked.
pub(crate) fn read_scenario(answers: ReadAnswers) -> (IamState, ReadAsked) {
    let asked = ReadAsked::default();
    let ReadAnswers { page, one, diff } = answers;
    let pages = Arc::clone(&asked.pages);
    let ones = Arc::clone(&asked.ones);
    let diffs = Arc::clone(&asked.diffs);
    let query_bus: Arc<dyn QueryBus> = Arc::new(
        FakeQueryBus::answering(move |query: GetGraphQlSpecsQuery| {
            record(&pages, query);
            page.clone().map_err(|refusal| refusal())
        })
        .and_answering(move |query: GetGraphQlSpecQuery| {
            record(&ones, query);
            one.clone().map_err(|refusal| refusal())
        })
        .and_answering(move |query: GetGraphQlSpecDiffQuery| {
            record(&diffs, query.id);
            diff.clone().map_err(|refusal| refusal())
        }),
    );
    let state = IamState {
        command_bus: Arc::new(FakeCommandBus::unregistered()),
        query_bus,
        uuid_generator: Arc::new(SequenceUuidGenerator::starting_at(1)),
        clock: Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        request_digester: Arc::new(FakeRequestDigester),
    };
    (state, asked)
}
