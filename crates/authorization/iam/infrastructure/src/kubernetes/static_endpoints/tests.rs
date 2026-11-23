use std::path::PathBuf;

use iam_domain::{EndpointWatch as _, SliceChange, WatchTarget};

use super::{StaticEndpointWatch, StaticEndpointsError};

/// A file of its own in the temporary directory, removed when the test ends.
struct TempFile(PathBuf);

impl TempFile {
    fn with(name: &str, content: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "static-endpoints-{}-{name}.json",
            std::process::id()
        ));
        std::fs::write(&path, content).unwrap();
        Self(path)
    }

    fn rewrite(&self, content: &str) {
        std::fs::write(&self.0, content).unwrap();
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap_or_default();
    }
}

fn target(service: &str) -> WatchTarget {
    WatchTarget {
        namespace: "vilnacrm".to_owned(),
        service: service.to_owned(),
    }
}

const FILE: &str = r#"{
    "user-service": [
        {"address": "user-service", "port": 8081, "zone": "zone-a"},
        {"address": "10.0.0.2", "port": 8081, "zone": "zone-b", "ready": false, "pod": "user-service-1"}
    ],
    "iam-gateway-peers": [{"address": "10.0.9.1", "port": 9090, "zone": "zone-c", "pod": "iam-gateway-0"}]
}"#;

#[tokio::test]
async fn a_service_lists_its_endpoints_with_defaults_for_the_conditions() {
    let file = TempFile::with("list", FILE);
    let watch = StaticEndpointWatch::new(&file.0).unwrap();

    let listing = watch.list(&target("user-service")).await.unwrap();

    let endpoints = &listing.slices.first().unwrap().endpoints;
    assert_eq!(endpoints.len(), 2);
    assert!(endpoints.first().unwrap().is_offered());
    assert!(!endpoints[1].is_offered());
    assert_eq!(endpoints[1].pod(), Some("user-service-1"));
    assert_eq!(listing.resource_version.len(), 64);
}

#[tokio::test]
async fn an_unlisted_service_has_no_slice() {
    let file = TempFile::with("unlisted", FILE);
    let watch = StaticEndpointWatch::new(&file.0).unwrap();

    let listing = watch.list(&target("billing")).await.unwrap();

    assert_eq!(listing.slices.len(), 0);
}

#[tokio::test]
async fn the_services_of_the_file_are_listed_by_name() {
    let file = TempFile::with("services", FILE);
    let watch = StaticEndpointWatch::new(&file.0).unwrap();

    assert_eq!(
        watch.services().unwrap(),
        vec!["iam-gateway-peers".to_owned(), "user-service".to_owned()]
    );
}

#[tokio::test]
async fn an_unchanged_file_ends_the_watch_without_changes() {
    let file = TempFile::with("unchanged", FILE);
    let watch = StaticEndpointWatch::new(&file.0).unwrap();
    let version = watch
        .list(&target("user-service"))
        .await
        .unwrap()
        .resource_version;

    let batch = watch
        .watch(&target("user-service"), &version)
        .await
        .unwrap();

    assert_eq!(batch.changes.len(), 0);
    assert_eq!(batch.resource_version, version);
}

#[tokio::test]
async fn a_changed_file_is_a_watch_event() {
    let file = TempFile::with("changed", FILE);
    let watch = StaticEndpointWatch::new(&file.0).unwrap();
    let version = watch
        .list(&target("user-service"))
        .await
        .unwrap()
        .resource_version;

    file.rewrite(r#"{"user-service": [{"address": "10.0.0.3", "port": 8081}]}"#);
    let batch = watch
        .watch(&target("user-service"), &version)
        .await
        .unwrap();

    assert_ne!(batch.resource_version, version);
    assert!(
        matches!(batch.changes.first(), Some(SliceChange::Upserted(slice)) if slice.endpoints.len() == 1)
    );
}

#[tokio::test]
async fn a_service_that_leaves_the_file_loses_its_slice() {
    let file = TempFile::with("removed", FILE);
    let watch = StaticEndpointWatch::new(&file.0).unwrap();
    let version = watch
        .list(&target("user-service"))
        .await
        .unwrap()
        .resource_version;

    file.rewrite("{}");
    let batch = watch
        .watch(&target("user-service"), &version)
        .await
        .unwrap();

    assert_eq!(
        batch.changes,
        vec![SliceChange::Removed("static".to_owned())]
    );
}

#[tokio::test]
async fn a_file_that_breaks_after_the_start_is_an_unavailable_source() {
    let file = TempFile::with("broken", FILE);
    let watch = StaticEndpointWatch::new(&file.0).unwrap();

    file.rewrite("not json");

    assert!(watch.list(&target("user-service")).await.is_err());
    assert!(watch.watch(&target("user-service"), "x").await.is_err());
}

#[test]
fn a_missing_file_is_refused() {
    let missing = std::env::temp_dir().join("static-endpoints-does-not-exist.json");

    assert!(matches!(
        StaticEndpointWatch::new(&missing),
        Err(StaticEndpointsError::Read(_))
    ));
}

#[test]
fn an_unparsable_file_is_refused() {
    let file = TempFile::with("unparsable", "[1, 2");

    assert!(matches!(
        StaticEndpointWatch::new(&file.0),
        Err(StaticEndpointsError::Parse(_))
    ));
}

#[test]
fn an_entry_without_an_address_or_with_a_bad_zone_is_refused() {
    let empty = TempFile::with("empty-address", r#"{"s": [{"address": "", "port": 80}]}"#);
    let zone = TempFile::with(
        "bad-zone",
        r#"{"s": [{"address": "a", "port": 80, "zone": "no zone"}]}"#,
    );

    assert!(matches!(
        StaticEndpointWatch::new(&empty.0),
        Err(StaticEndpointsError::Entry { .. })
    ));
    let error = StaticEndpointWatch::new(&zone.0).unwrap_err();
    assert!(error.to_string().contains("zone"));
}
