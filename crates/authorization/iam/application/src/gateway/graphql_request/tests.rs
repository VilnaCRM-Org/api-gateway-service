use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use iam_domain::{
    DecisionReason, DocumentCache, GqlName, GraphQlCoordinate, GraphQlField, GraphQlTypeGraph,
    PermissionFlags, ServiceCatalog, ServiceName,
};
use test_support::log::LogRecorder;
use test_support::policy_epoch::seeded_policy_epoch;
use tokio::time::Instant;

use crate::document_cache_fixtures::MapDocumentCache;

use super::{
    Analysis, BLOCKING_THRESHOLD_BYTES, GraphQlOperation, GraphQlRequestAnalyzer, PRUNE_ABOVE,
    ParseBudget, ParseBudgetSettings, ParseObserver, ParseSite, Window, ratio, spend,
};

fn service() -> ServiceName {
    ServiceName::new("orders").unwrap()
}

fn catalog() -> ServiceCatalog {
    let field = |coordinate: &str, return_type: &str| {
        (
            GraphQlCoordinate::parse(coordinate).unwrap(),
            GraphQlField {
                return_type: GqlName::parse(return_type).unwrap(),
                flags: PermissionFlags::NONE,
            },
        )
    };
    let graph = GraphQlTypeGraph::new(
        [
            field("Query.orders", "Order"),
            field("Order.id", "ID"),
            field("Order.total", "Int"),
        ],
        [],
    )
    .unwrap();
    ServiceCatalog::new(service(), seeded_policy_epoch(), Vec::new(), vec![graph])
}

fn operation(document: &str) -> GraphQlOperation {
    GraphQlOperation {
        document: document.to_owned(),
        operation_name: None,
    }
}

/// A document of `Query.orders` that no other document of the same `number` equals.
fn distinct(number: u32) -> GraphQlOperation {
    operation(&format!("query Q{number} {{ orders {{ id }} }}"))
}

#[derive(Debug, Default)]
struct Sites {
    seen: Mutex<Vec<(ParseSite, Option<String>)>>,
}

impl ParseObserver for Sites {
    fn parsed(&self, site: ParseSite, _bytes: usize) {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((site, std::thread::current().name().map(str::to_owned)));
    }
}

fn analyzer(cache: &Arc<MapDocumentCache>) -> GraphQlRequestAnalyzer {
    let cache: Arc<dyn DocumentCache> = Arc::<MapDocumentCache>::clone(cache);
    GraphQlRequestAnalyzer::new(cache, ParseBudgetSettings::default())
}

#[tokio::test]
async fn the_coordinates_of_every_operation_of_a_batch_are_merged() {
    let analyzer = analyzer(&Arc::default());

    let analysis = analyzer
        .analyze(
            &catalog(),
            "subject",
            &[
                operation("{ orders { id } }"),
                operation("{ orders { total } }"),
            ],
        )
        .await;

    let Analysis::Analyzed(document) = analysis else {
        panic!("not analysed: {analysis:?}");
    };
    for coordinate in ["Order.id", "Order.total"] {
        assert!(
            document
                .coordinates()
                .contains(&GraphQlCoordinate::parse(coordinate).unwrap()),
            "{coordinate} missing"
        );
    }
}

#[tokio::test]
async fn a_request_without_operations_is_malformed() {
    let analysis = analyzer(&Arc::default())
        .analyze(&catalog(), "subject", &[])
        .await;

    assert_eq!(
        analysis,
        Analysis::Refused(DecisionReason::MalformedOperation)
    );
}

#[tokio::test]
async fn a_document_without_a_coordinate_is_malformed() {
    let analysis = analyzer(&Arc::default())
        .analyze(&catalog(), "subject", &[operation("{ __typename }")])
        .await;

    assert_eq!(
        analysis,
        Analysis::Refused(DecisionReason::MalformedOperation)
    );
}

#[tokio::test]
async fn a_field_that_no_version_has_is_an_unknown_operation() {
    let analysis = analyzer(&Arc::default())
        .analyze(&catalog(), "subject", &[operation("{ invoices { id } }")])
        .await;

    assert_eq!(
        analysis,
        Analysis::Refused(DecisionReason::UnknownOperation)
    );
}

#[tokio::test]
async fn an_introspection_query_is_analysed_as_an_introspection() {
    let analysis = analyzer(&Arc::default())
        .analyze(
            &catalog(),
            "subject",
            &[operation("{ __schema { queryType { name } } }")],
        )
        .await;

    let Analysis::Analyzed(document) = analysis else {
        panic!("not analysed: {analysis:?}");
    };
    assert!(document.introspection());
}

#[tokio::test]
async fn a_document_that_was_analysed_is_served_from_the_cache() {
    let cache = Arc::new(MapDocumentCache::default());
    let analyzer = analyzer(&cache);
    let same = [operation("{ orders { id } }")];

    let first = analyzer.analyze(&catalog(), "subject", &same).await;
    let second = analyzer.analyze(&catalog(), "subject", &same).await;

    assert_eq!(first, second);
    assert_eq!(cache.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn the_twenty_first_uncached_document_of_a_second_is_rate_limited_and_cached_ones_are_served()
{
    let cache = Arc::new(MapDocumentCache::default());
    let analyzer = analyzer(&cache);
    for number in 0..20 {
        let analysis = analyzer
            .analyze(&catalog(), "subject", &[distinct(number)])
            .await;
        assert!(matches!(analysis, Analysis::Analyzed(_)), "{number}");
    }

    let over = analyzer
        .analyze(&catalog(), "subject", &[distinct(20)])
        .await;
    let cached = analyzer
        .analyze(&catalog(), "subject", &[distinct(0)])
        .await;
    let other = analyzer
        .analyze(&catalog(), "another", &[distinct(21)])
        .await;
    tokio::time::advance(Duration::from_secs(1)).await;
    let later = analyzer
        .analyze(&catalog(), "subject", &[distinct(20)])
        .await;

    assert_eq!(over, Analysis::RateLimited);
    assert!(matches!(cached, Analysis::Analyzed(_)));
    assert!(matches!(other, Analysis::Analyzed(_)));
    assert!(matches!(later, Analysis::Analyzed(_)));
}

#[tokio::test(start_paused = true)]
async fn the_bytes_a_subject_has_parsed_in_a_second_are_bounded() {
    let budget = ParseBudget::new(ParseBudgetSettings {
        misses_per_second: 100,
        bytes_per_second: 1_000,
    });

    assert!(budget.charge("subject", 600));
    assert!(!budget.charge("subject", 600));
    assert!(budget.charge("subject", 400));
    assert!(budget.charge("another", 1_000));
}

#[tokio::test]
async fn a_document_above_the_threshold_is_parsed_on_the_blocking_pool_and_a_small_one_inline() {
    let sites = Arc::new(Sites::default());
    let analyzer = analyzer(&Arc::default()).with_observer(Arc::<Sites>::clone(&sites));
    let padding = " ".repeat(BLOCKING_THRESHOLD_BYTES * 5);
    let large = operation(&format!("{{ orders {{ id }} }}{padding}"));

    let large = analyzer.analyze(&catalog(), "subject", &[large]).await;
    let small = analyzer
        .analyze(&catalog(), "subject", &[operation("{ orders { id } }")])
        .await;

    assert!(matches!(large, Analysis::Analyzed(_)));
    assert!(matches!(small, Analysis::Analyzed(_)));
    let seen = sites.seen.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(
        seen.iter().map(|(site, _)| *site).collect::<Vec<_>>(),
        [ParseSite::BlockingPool, ParseSite::Worker]
    );
    assert_ne!(seen[0].1, seen[1].1);
}

#[test]
fn the_hit_ratio_scales_down_with_its_counters() {
    assert!((ratio(1, 2) - 0.5).abs() < f64::EPSILON);
    assert!(ratio(0, 0).abs() < f64::EPSILON);
    assert!((ratio(u64::MAX / 2, u64::MAX) - 0.5).abs() < 0.001);
}

/// An observer whose parse panics, so that the blocking task ends without an answer.
#[derive(Debug)]
struct Panicking;

impl ParseObserver for Panicking {
    fn parsed(&self, _site: ParseSite, _bytes: usize) {
        panic!("the parse of this document fails");
    }
}

#[tokio::test]
async fn a_blocking_parse_that_does_not_finish_is_unavailable() {
    let analyzer = analyzer(&Arc::default()).with_observer(Arc::new(Panicking));
    let padding = " ".repeat(BLOCKING_THRESHOLD_BYTES * 2);
    let large = operation(&format!("{{ orders {{ id }} }}{padding}"));

    let analysis = analyzer.analyze(&catalog(), "subject", &[large]).await;

    assert_eq!(analysis, Analysis::Unavailable);
}

#[tokio::test]
async fn every_lookup_emits_the_hit_ratio_of_the_document_cache() {
    let (recorder, _guard) = LogRecorder::install();
    let analyzer = analyzer(&Arc::default());
    let same = [operation("{ orders { id } }")];

    analyzer.analyze(&catalog(), "subject", &same).await;
    analyzer.analyze(&catalog(), "subject", &same).await;

    let ratios: Vec<Option<String>> = recorder
        .lines()
        .iter()
        .filter(|line| line.field("metric") == Some("graphql_document_cache_hit_ratio"))
        .map(|line| line.field("value").map(str::to_owned))
        .collect();
    assert_eq!(ratios, [Some("0.0".to_owned()), Some("0.5".to_owned())]);
}

#[tokio::test]
async fn the_windows_that_have_ended_are_dropped_once_there_are_too_many() {
    let now = Instant::now();
    let mut windows: HashMap<String, Window> = (0..PRUNE_ABOVE)
        .map(|number| (format!("subject-{number}"), Window::opened(now)))
        .collect();
    let settings = ParseBudgetSettings::default();

    let charged = spend(
        &mut windows,
        settings,
        ("newcomer", 10),
        now + Duration::from_secs(2),
    );

    assert!(charged);
    assert_eq!(windows.len(), 1);
}
