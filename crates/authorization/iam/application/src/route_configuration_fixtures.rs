//! Values and doubles that the tests of the route-configuration operations share: the REST and the
//! GraphQL adapters over a command bus and a query bus that answer as told and record what they
//! were asked.

use std::sync::{Arc, PoisonError};
use std::time::SystemTime;

use iam_domain::{
    ChangeReceipt, HttpMethod, RouteFields, RouteHost, RouteParts, RouteSetDiff, RouteSetVersion,
};
use shared_domain::{CommandBus, QueryBus};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::request_digester::FakeRequestDigester;
use test_support::route::route_draft;

use crate::command::apply_route_configuration::ApplyRouteConfigurationCommand;
use crate::fixtures::Refusal;
use crate::http::IamState;
use crate::query::get_change_receipt::GetChangeReceiptQuery;
use crate::query::get_route_configuration::{GetRouteConfigurationQuery, RouteConfiguration};
use crate::query::preview_route_configuration::{
    PreviewRouteConfigurationQuery, RouteConfigurationPreview,
};
use crate::route_fixtures::{HOST, numbered_id, receipt_at, route_at, upstream_id};
pub(crate) use crate::upstream_fixtures::{Log, recorded};

fn record<T>(log: &Log<T>, value: T) {
    log.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(value);
}

/// The fields of a route on `HOST` that serves `GET` under `path`.
pub(crate) fn declared(path: &str) -> RouteFields {
    RouteFields::new(&route_draft(
        HOST,
        path,
        &[HttpMethod::Get],
        "core",
        upstream_id(),
    ))
    .unwrap()
}

/// The stored routes `/a` and `/b`, each at version 3.
pub(crate) fn stored() -> Vec<RouteParts> {
    vec![
        route_at(numbered_id(1), "/a", &[HttpMethod::Get], 3),
        route_at(numbered_id(2), "/b", &[HttpMethod::Get], 3),
    ]
}

/// The set of the stored routes `/a` and `/b`, with its version.
pub(crate) fn configuration() -> RouteConfiguration {
    let routes = stored();
    RouteConfiguration {
        host: RouteHost::new(HOST).unwrap(),
        version: RouteSetVersion::of(&routes),
        routes,
    }
}

/// The preview of the declared routes `declared` against the stored routes `/a` and `/b`.
pub(crate) fn preview(declared: Vec<RouteFields>) -> RouteConfigurationPreview {
    let routes = stored();
    let diff = RouteSetDiff::between(&routes, declared);
    RouteConfigurationPreview {
        host: RouteHost::new(HOST).unwrap(),
        version: RouteSetVersion::of(&routes),
        route_count: routes.len().saturating_add(diff.added().len()),
        diff,
    }
}

/// The receipt of an application that left the set at the version `version`.
pub(crate) fn receipt_of(version: i64, policy_version: Option<i64>) -> ChangeReceipt {
    receipt_at(version, policy_version)
}

/// What the doubles answer.
pub(crate) struct Answers {
    /// The answer of the change-receipt query.
    pub receipt: ChangeReceipt,
    /// The answer of the dry-run query.
    pub preview: Result<RouteConfigurationPreview, Refusal>,
    /// The answer of the route-configuration query.
    pub configuration: Result<RouteConfiguration, Refusal>,
    /// The answer of the apply command.
    pub apply: Result<(), Refusal>,
}

impl Default for Answers {
    /// A set that adds `/c`, changes nothing else and removes nothing, applied at version 5.
    fn default() -> Self {
        Self {
            receipt: receipt_of(5, Some(8)),
            preview: Ok(preview(vec![
                declared("/a"),
                declared("/b"),
                declared("/c"),
            ])),
            configuration: Ok(configuration()),
            apply: Ok(()),
        }
    }
}

/// What the doubles were asked.
#[derive(Debug, Default)]
pub(crate) struct Asked {
    /// The apply commands that were dispatched.
    pub applies: Log<ApplyRouteConfigurationCommand>,
    /// The dry-run queries.
    pub previews: Log<PreviewRouteConfigurationQuery>,
    /// The route-configuration queries.
    pub configurations: Log<GetRouteConfigurationQuery>,
}

/// The state over doubles that answer as `answers` say and record what they were asked, with the
/// two buses to read their asked names.
pub(crate) fn scenario(
    answers: Answers,
) -> (IamState, Arc<FakeCommandBus>, Arc<FakeQueryBus>, Asked) {
    let asked = Asked::default();
    let applies = Arc::clone(&asked.applies);
    let apply = answers.apply;
    let commands = Arc::new(FakeCommandBus::handling(
        move |command: ApplyRouteConfigurationCommand| {
            record(&applies, command);
            apply.map_err(|refusal| refusal())
        },
    ));
    let previews = Arc::clone(&asked.previews);
    let configurations = Arc::clone(&asked.configurations);
    let (receipt, preview, configuration) =
        (answers.receipt, answers.preview, answers.configuration);
    let queries = Arc::new(
        FakeQueryBus::answering(move |query: PreviewRouteConfigurationQuery| {
            record(&previews, query);
            preview.clone().map_err(|refusal| refusal())
        })
        .and_answering(move |query: GetRouteConfigurationQuery| {
            record(&configurations, query);
            configuration.clone().map_err(|refusal| refusal())
        })
        .and_answering(move |_query: GetChangeReceiptQuery| Ok(receipt.clone())),
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
    (state, commands, queries, asked)
}
