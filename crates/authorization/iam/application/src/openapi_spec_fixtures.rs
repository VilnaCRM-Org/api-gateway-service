//! Values and doubles that the tests of the `OpenAPI` specification operations of the REST and
//! GraphQL adapters share.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, ContentHash, HttpMethod, OpenApiSpecContent, OpenApiSpecParts, PathTemplate,
    PermissionFlags, RestOperation, RestOperationSet, RestSpecDiff, ServiceName, SpecId,
    SpecStatus,
};
use shared_domain::{CommandBus, QueryBus, Uuid};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::request_digester::FakeRequestDigester;

use crate::command::load_openapi_spec::LoadOpenApiSpecCommand;
use crate::error::IamError;
use crate::fixtures::USER;
use crate::http::IamState;
use crate::query::find_openapi_spec::FindOpenApiSpecQuery;
use crate::query::get_openapi_spec::GetOpenApiSpecQuery;
use crate::query::get_openapi_spec_diff::{GetOpenApiSpecDiffQuery, OpenApiSpecView};
use crate::query::get_openapi_specs::{GetOpenApiSpecsQuery, OpenApiSpecPage, OpenApiSpecSummary};

/// The version that every answer names.
pub(crate) const SPEC: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";

/// A bus error that a test builds when it needs it.
pub(crate) type Refusal = fn() -> IamError;

/// What the doubles answer.
pub(crate) struct Answers {
    /// The version that already holds the document, when the answer to the lookup is one.
    pub existing: Result<Option<SpecId>, Refusal>,
    /// The answer of the version query.
    pub view: Result<Option<OpenApiSpecView>, Refusal>,
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
    pub commands: Arc<Mutex<Vec<LoadOpenApiSpecCommand>>>,
    /// The lookups by content hash.
    pub finds: Arc<Mutex<Vec<FindOpenApiSpecQuery>>>,
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

/// A draft version of `billing` with the operation `GET /invoices` and its diff against nothing.
pub(crate) fn view() -> OpenApiSpecView {
    let mut operations = RestOperationSet::new();
    operations
        .insert(RestOperation {
            method: HttpMethod::Get,
            template: PathTemplate::from_openapi_path("/invoices").unwrap(),
            label: Some("listInvoices".to_owned()),
            flags: PermissionFlags::NONE,
        })
        .unwrap();
    let service = ServiceName::new("billing").unwrap();
    let diff = RestSpecDiff::compute(&service, &operations, &RestOperationSet::new(), &[]);
    let spec = OpenApiSpecParts {
        id: SpecId::parse(SPEC).unwrap(),
        content: OpenApiSpecContent {
            service,
            content_hash: ContentHash::new(&[0xab; 32]).unwrap(),
            operations,
        },
        status: SpecStatus::Draft,
        uploaded_by: ActorRef::User(Uuid::parse(USER).unwrap()),
        created_at: at(86_400),
        activated_at: None,
        retired_at: None,
    };
    OpenApiSpecView {
        operation_count: 1,
        diff,
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
        move |load: LoadOpenApiSpecCommand| {
            record(&commands, load);
            command.map_err(|refusal| refusal())
        },
    ));
    let finds = Arc::clone(&asked.finds);
    let reads = Arc::clone(&asked.reads);
    let query_bus: Arc<dyn QueryBus> = Arc::new(
        FakeQueryBus::answering(move |query: FindOpenApiSpecQuery| {
            record(&finds, query);
            existing.map_err(|refusal| refusal())
        })
        .and_answering(move |query: GetOpenApiSpecDiffQuery| {
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
    pub page: Result<OpenApiSpecPage, Refusal>,
    /// The answer of the query of one version.
    pub one: Result<Option<OpenApiSpecSummary>, Refusal>,
    /// The answer of the diff query.
    pub diff: Result<Option<OpenApiSpecView>, Refusal>,
}

impl Default for ReadAnswers {
    fn default() -> Self {
        Self {
            page: Ok(OpenApiSpecPage {
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
    pub pages: Arc<Mutex<Vec<GetOpenApiSpecsQuery>>>,
    /// The queries of one version.
    pub ones: Arc<Mutex<Vec<GetOpenApiSpecQuery>>>,
    /// The diff queries.
    pub diffs: Arc<Mutex<Vec<SpecId>>>,
}

/// The version of [`view`] without its diff and without a document.
pub(crate) fn summary() -> OpenApiSpecSummary {
    let view = view();
    OpenApiSpecSummary {
        spec: view.spec,
        operation_count: view.operation_count,
        document: None,
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
        FakeQueryBus::answering(move |query: GetOpenApiSpecsQuery| {
            record(&pages, query);
            page.clone().map_err(|refusal| refusal())
        })
        .and_answering(move |query: GetOpenApiSpecQuery| {
            record(&ones, query);
            one.clone().map_err(|refusal| refusal())
        })
        .and_answering(move |query: GetOpenApiSpecDiffQuery| {
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
