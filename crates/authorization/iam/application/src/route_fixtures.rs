//! Values and doubles that the tests of the route operations share: the commands, the queries and
//! the REST and GraphQL adapters.

use std::collections::BTreeMap;
use std::sync::{Arc, PoisonError};
use std::time::{Duration, SystemTime};

use iam_domain::{
    AssignmentScope, AuditTarget, ChangeReceipt, CompiledRoleSet, EntityVersion, HttpMethod,
    IamUnitOfWork, PermissionGrant, PermissionGrantSet, PolicyReadRepository, PolicyVersion,
    RatePolicyParts, RatePolicyRepository, RejectedAttemptLog, RoleAssignment, RoleId,
    RouteConflict, RouteConflictGuard, RouteFields, RouteHost, RouteId, RouteMatcher, RouteParts,
    RouteRepository, RouteTableCompiler, SubjectPolicy, SubjectRef, UpstreamId, UpstreamParts,
    UpstreamRepository,
};
use shared_domain::{CommandBus, QueryBus, Uuid};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::policy_epoch::seeded_policy_epoch;
use test_support::policy_read::FakePolicyReadRepository;
use test_support::rate_policy::FakeRatePolicyRepository;
use test_support::request_digester::FakeRequestDigester;
use test_support::route::{FakeRouteRepository, route_draft};
use test_support::unit_of_work::FakeIamUnitOfWork;
use test_support::upstream::FakeUpstreamRepository;

use crate::command::create_route::CreateRouteCommand;
use crate::command::delete_route::DeleteRouteCommand;
use crate::command::route_checks::RoutePorts;
use crate::command::update_route::UpdateRouteCommand;
use crate::fixtures::{Refusal, USER};
use crate::http::IamState;
use crate::query::get_change_receipt::GetChangeReceiptQuery;
use crate::query::get_idempotent_replay::GetIdempotentReplayQuery;
use crate::query::get_route::GetRouteQuery;
use crate::query::list_routes::{ListRoutesQuery, RoutePage};
use crate::rejected_attempt_fixtures::FakeRejectedAttemptLog;
use crate::upstream_fixtures::upstream_named;
pub(crate) use crate::upstream_fixtures::{Log, actor, at, change_id, recorded};

/// The route that every answer names.
pub(crate) const ROUTE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890e0";
/// The upstream that the fixture routes forward to.
pub(crate) const UPSTREAM: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890cf";
/// The host of the fixture routes.
pub(crate) const HOST: &str = "app.example.test";

/// The id of the route that every answer names.
pub(crate) fn route_id() -> RouteId {
    RouteId::parse(ROUTE).unwrap()
}

/// The id of the route with the number `number`.
pub(crate) fn numbered_id(number: u32) -> RouteId {
    RouteId::parse(&format!("0190f2a8-7b3c-7d4e-8f10-{number:012x}")).unwrap()
}

/// The id of the upstream that the fixture routes forward to.
pub(crate) fn upstream_id() -> UpstreamId {
    UpstreamId::parse(UPSTREAM).unwrap()
}

/// The stored state of the route `id` on `HOST` for `path` and `methods`, of the service `core`,
/// at `version`.
pub(crate) fn route_at(
    id: RouteId,
    path: &str,
    methods: &[HttpMethod],
    version: i64,
) -> RouteParts {
    let draft = route_draft(HOST, path, methods, "core", upstream_id());
    RouteParts {
        id,
        fields: RouteFields::new(&draft).unwrap(),
        system: false,
        version: EntityVersion::new(version).unwrap(),
        created_at: at(),
        updated_at: at().checked_add(Duration::from_mins(5)).unwrap(),
        deleted_at: None,
    }
}

/// The stored state of the route that every answer names: `GET /api/orders/{id}`, at `version`.
pub(crate) fn route(version: i64) -> RouteParts {
    route_at(route_id(), "/api/orders/{id}", &[HttpMethod::Get], version)
}

/// The receipt of the creation of the route at version 1.
pub(crate) fn receipt(policy_version: Option<i64>) -> ChangeReceipt {
    receipt_at(1, policy_version)
}

/// The receipt of a change that left the route at `version`.
pub(crate) fn receipt_at(version: i64, policy_version: Option<i64>) -> ChangeReceipt {
    ChangeReceipt::new(
        change_id(),
        actor(),
        AuditTarget::new("route", ROUTE).unwrap(),
        EntityVersion::new(version).unwrap(),
        policy_version.map(|value| PolicyVersion::new(value).unwrap()),
    )
}

/// A compiler that refuses the routes of a host that conflict as the guard says, and otherwise
/// builds a matcher that finds nothing.
#[derive(Debug, Default)]
pub(crate) struct FakeRouteTableCompiler {
    refusing: Option<RouteConflict>,
}

impl FakeRouteTableCompiler {
    /// A compiler that accepts every set the guard accepts.
    pub(crate) const fn new() -> Self {
        Self { refusing: None }
    }

    /// A compiler that refuses every set with `conflict`.
    pub(crate) const fn refusing(conflict: RouteConflict) -> Self {
        Self {
            refusing: Some(conflict),
        }
    }
}

#[derive(Debug)]
struct EmptyMatcher;

impl RouteMatcher for EmptyMatcher {
    fn find(&self, _method: HttpMethod, _path: &str) -> Option<RouteId> {
        None
    }
}

impl RouteTableCompiler for FakeRouteTableCompiler {
    fn compile(
        &self,
        _host: &RouteHost,
        routes: &[RouteParts],
    ) -> Result<Box<dyn RouteMatcher>, RouteConflict> {
        if let Some(conflict) = self.refusing {
            return Err(conflict);
        }
        RouteConflictGuard::check_set(routes)?;
        Ok(Box::new(EmptyMatcher))
    }
}

/// What the doubles answer.
pub(crate) struct Answers {
    /// The answer of the idempotent-replay query.
    pub replay: Result<Option<ChangeReceipt>, Refusal>,
    /// The answer of the change-receipt query.
    pub receipt: ChangeReceipt,
    /// The answer of the route query.
    pub route: Result<Option<RouteParts>, Refusal>,
    /// The answer of the route-list query.
    pub page: Result<RoutePage, Refusal>,
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
            route: Ok(Some(route(1))),
            page: Ok(RoutePage {
                routes: Vec::new(),
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
    pub commands: Log<CreateRouteCommand>,
    /// The update commands that were dispatched.
    pub updates: Log<UpdateRouteCommand>,
    /// The delete commands that were dispatched.
    pub deletions: Log<DeleteRouteCommand>,
    /// The route queries.
    pub routes: Log<RouteId>,
    /// The route-list queries.
    pub lists: Log<ListRoutesQuery>,
    /// The idempotent-replay queries.
    pub replays: Log<GetIdempotentReplayQuery>,
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
    FakeCommandBus::handling(move |command: CreateRouteCommand| {
        record(&log, command);
        answer.map_err(|refusal| refusal())
    })
    .and_handling(move |command: UpdateRouteCommand| {
        record(&updates, command);
        update.map_err(|refusal| refusal())
    })
    .and_handling(move |command: DeleteRouteCommand| {
        record(&deletions, command);
        delete.map_err(|refusal| refusal())
    })
}

fn query_bus(answers: Answers, asked: &Asked) -> FakeQueryBus {
    let Answers {
        replay,
        receipt,
        route,
        page,
        ..
    } = answers;
    let replays = Arc::clone(&asked.replays);
    let routes = Arc::clone(&asked.routes);
    let lists = Arc::clone(&asked.lists);
    FakeQueryBus::answering(move |query: GetIdempotentReplayQuery| {
        record(&replays, query);
        replay.clone().map_err(|refusal| refusal())
    })
    .and_answering(move |_query: GetChangeReceiptQuery| Ok(receipt.clone()))
    .and_answering(move |query: GetRouteQuery| {
        record(&routes, query.id);
        route.clone().map_err(|refusal| refusal())
    })
    .and_answering(move |query: ListRoutesQuery| {
        record(&lists, query);
        page.clone().map_err(|refusal| refusal())
    })
}

/// The policy of the user that acts, holding `grants` at global scope.
pub(crate) fn policy_holding(grants: &[&str]) -> SubjectPolicy {
    let role_id = RoleId::parse("0190f2a8-7b3c-7d4e-8f10-000000000a01").unwrap();
    let set = CompiledRoleSet::from_active(
        &PermissionGrantSet::new(
            grants
                .iter()
                .map(|text| PermissionGrant::parse(text).unwrap()),
        )
        .unwrap(),
    );
    SubjectPolicy::new(
        seeded_policy_epoch(),
        vec![RoleAssignment::new(role_id, AssignmentScope::Global, None)],
        BTreeMap::from([(role_id, set)]),
    )
}

/// What the stores of a route command hold.
pub(crate) struct Stores {
    /// The stored routes.
    pub routes: Vec<RouteParts>,
    /// The stored upstreams.
    pub upstreams: Vec<UpstreamParts>,
    /// The stored rate policies.
    pub rate_policies: Vec<RatePolicyParts>,
    /// The compiler of the candidate route table.
    pub compiler: FakeRouteTableCompiler,
    /// The policy of the user that acts; none holds no key.
    pub policy: Option<SubjectPolicy>,
    /// The unit of work that commits.
    pub unit_of_work: FakeIamUnitOfWork,
}

impl Default for Stores {
    /// The upstream `core` of the service `core` and nothing else.
    fn default() -> Self {
        Self {
            routes: Vec::new(),
            upstreams: vec![upstream_named(upstream_id(), "core", "core", 1)],
            rate_policies: Vec::new(),
            compiler: FakeRouteTableCompiler::new(),
            policy: None,
            unit_of_work: FakeIamUnitOfWork::new(),
        }
    }
}

/// The ports of a route command over `stores`, with the doubles that tests read back.
pub(crate) struct RouteWorld {
    /// The unit of work that recorded the commits.
    pub unit_of_work: Arc<FakeIamUnitOfWork>,
    /// The buffer that recorded the refusals.
    pub attempts: Arc<FakeRejectedAttemptLog>,
    /// The ports for the handler under test.
    pub ports: RoutePorts,
}

/// The world of a route command over `stores`.
pub(crate) fn route_world(stores: Stores) -> RouteWorld {
    let unit_of_work = Arc::new(stores.unit_of_work);
    let attempts = Arc::new(FakeRejectedAttemptLog::new());
    let mut policies = FakePolicyReadRepository::new();
    if let Some(policy) = stores.policy {
        policies = policies.with_subject(SubjectRef::user(Uuid::parse(USER).unwrap()), policy);
    }
    let committing: Arc<dyn IamUnitOfWork> = Arc::<FakeIamUnitOfWork>::clone(&unit_of_work);
    let log: Arc<dyn RejectedAttemptLog> = Arc::<FakeRejectedAttemptLog>::clone(&attempts);
    let upstreams: Arc<dyn UpstreamRepository> =
        Arc::new(FakeUpstreamRepository::holding(stores.upstreams));
    let rate_policies: Arc<dyn RatePolicyRepository> =
        Arc::new(FakeRatePolicyRepository::holding(stores.rate_policies));
    let routes: Arc<dyn RouteRepository> = Arc::new(FakeRouteRepository::holding(stores.routes));
    let policies: Arc<dyn PolicyReadRepository> = Arc::new(policies);
    RouteWorld {
        unit_of_work,
        attempts,
        ports: RoutePorts {
            upstreams,
            rate_policies,
            routes,
            compiler: Arc::new(stores.compiler),
            policies,
            unit_of_work: committing,
            rejected_attempts: log,
        },
    }
}
