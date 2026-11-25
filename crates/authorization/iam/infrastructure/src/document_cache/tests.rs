use std::time::Duration;

use iam_domain::{
    AnalyzedDocument, CoordinateSet, DocumentCache as _, DocumentKey, GraphQlCoordinate,
    PermissionFlags, PolicyVersion, ServiceName,
};

use super::{DocumentCacheSettings, MokaDocumentCache};

fn cache(capacity_bytes: u64) -> MokaDocumentCache {
    MokaDocumentCache::new(DocumentCacheSettings {
        capacity_bytes,
        time_to_idle: Duration::from_secs(60),
    })
}

fn service(name: &str) -> ServiceName {
    ServiceName::new(name).unwrap()
}

fn key(document: &str) -> DocumentKey {
    DocumentKey::of(document, None, PolicyVersion::new(1).unwrap())
}

fn analyzed(coordinate: &str) -> AnalyzedDocument {
    let mut coordinates = CoordinateSet::new();
    coordinates.insert(
        GraphQlCoordinate::parse(coordinate).unwrap(),
        PermissionFlags::NONE,
    );
    AnalyzedDocument::new(coordinates, false)
}

#[test]
fn a_stored_analysis_is_served_for_the_same_service_key_and_text() {
    let cache = cache(1 << 20);
    cache.insert(
        &service("orders"),
        key("{ orders }"),
        "{ orders }",
        analyzed("Query.orders"),
    );

    let hit = cache.get(&service("orders"), key("{ orders }"), "{ orders }");

    assert_eq!(hit, Some(analyzed("Query.orders")));
}

#[test]
fn another_service_does_not_share_an_entry() {
    let cache = cache(1 << 20);
    cache.insert(
        &service("orders"),
        key("{ orders }"),
        "{ orders }",
        analyzed("Query.orders"),
    );

    assert_eq!(
        cache.get(&service("billing"), key("{ orders }"), "{ orders }"),
        None
    );
}

#[test]
fn two_documents_that_collide_on_the_hash_never_share_an_analysis() {
    let cache = cache(1 << 20);
    let collided = DocumentKey::from_digest(7);
    cache.insert(
        &service("orders"),
        collided,
        "{ orders }",
        analyzed("Query.orders"),
    );

    assert_eq!(
        cache.get(&service("orders"), collided, "{ invoices }"),
        None
    );
    assert_eq!(
        cache.get(&service("orders"), collided, "{ orders }"),
        Some(analyzed("Query.orders"))
    );
}

#[test]
fn the_cache_holds_no_more_than_its_weight() {
    let cache = cache(2_000);
    for number in 0..50 {
        let document = format!("{{ orders {{ id }} }} # {}", "x".repeat(500 + number));
        cache.insert(
            &service("orders"),
            key(&document),
            &document,
            analyzed("Query.orders"),
        );
    }

    assert!(cache.entry_count() < 50);
}
