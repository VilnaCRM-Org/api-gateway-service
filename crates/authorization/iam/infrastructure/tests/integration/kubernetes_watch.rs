//! `KubernetesEndpointWatch` against a fake Kubernetes API: the watched set follows every change
//! after one watch event, a dropped connection and a 410 lose no endpoint, and the adapter sends
//! only the read-only requests that its RBAC role grants (FR-87).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use iam_domain::{
    EndpointWatch as _, EndpointWatchError, SliceChange, UpstreamEndpoint, WatchBatch, WatchTarget,
};
use iam_infrastructure::{KubernetesEndpointWatch, KubernetesSettings};

mod fake_api;

use fake_api::{FakeEndpoint, FakeKubernetesApi};

/// One change of the watched set: its name, the endpoints of the slice and the offered addresses.
type Step<'a> = (&'a str, Vec<FakeEndpoint>, Vec<&'a str>);

/// A file of its own in the temporary directory, removed when the test ends.
struct TempFile(PathBuf);

impl TempFile {
    fn with(name: &str, content: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("kubernetes-watch-{}-{name}", std::process::id()));
        std::fs::write(&path, content).unwrap();
        Self(path)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap_or_default();
    }
}

fn target() -> WatchTarget {
    WatchTarget {
        namespace: "vilnacrm".to_owned(),
        service: "user-service".to_owned(),
    }
}

fn adapter(api: &FakeKubernetesApi, token_file: Option<PathBuf>) -> KubernetesEndpointWatch {
    KubernetesEndpointWatch::new(&KubernetesSettings {
        api_base: api.base_url(),
        token_file,
        ca_file: None,
        watch_timeout: Duration::from_secs(1),
    })
    .unwrap()
}

/// The endpoints the application would hold after folding `batch` into `slices`.
fn fold(slices: &mut BTreeMap<String, Vec<UpstreamEndpoint>>, batch: WatchBatch) {
    for change in batch.changes {
        match change {
            SliceChange::Upserted(slice) => {
                slices.insert(slice.name, slice.endpoints);
            }
            SliceChange::Removed(name) => {
                slices.remove(&name);
            }
        }
    }
}

fn offered(slices: &BTreeMap<String, Vec<UpstreamEndpoint>>) -> Vec<String> {
    let mut addresses: Vec<String> = slices
        .values()
        .flatten()
        .filter(|endpoint| endpoint.is_offered())
        .map(|endpoint| endpoint.address().to_owned())
        .collect();
    addresses.sort();
    addresses
}

async fn start(
    api: &FakeKubernetesApi,
) -> (
    KubernetesEndpointWatch,
    BTreeMap<String, Vec<UpstreamEndpoint>>,
    String,
) {
    let watch = adapter(api, None);
    let listing = watch.list(&target()).await.unwrap();
    let mut slices = BTreeMap::new();
    for slice in listing.slices {
        slices.insert(slice.name, slice.endpoints);
    }
    (watch, slices, listing.resource_version)
}

#[tokio::test]
async fn a_list_returns_the_slices_of_the_service_with_zone_and_conditions() {
    let api = FakeKubernetesApi::start().await;
    api.put_slice(
        "user-service-a",
        &[FakeEndpoint::ready("10.0.0.1", "zone-a")],
    );
    let (_watch, slices, version) = start(&api).await;

    let endpoint = slices["user-service-a"].first().unwrap();
    assert_eq!(endpoint.address(), "10.0.0.1");
    assert_eq!(endpoint.zone().unwrap().as_str(), "zone-a");
    assert!(endpoint.is_offered());
    assert_eq!(version, api.version().to_string());
}

#[tokio::test]
async fn every_change_shows_in_the_watched_set_after_one_watch_event() {
    let api = FakeKubernetesApi::start().await;
    api.put_slice(
        "user-service-a",
        &[FakeEndpoint::ready("10.0.0.1", "zone-a")],
    );
    let (watch, mut slices, mut version) = start(&api).await;
    assert_eq!(offered(&slices), ["10.0.0.1"]);

    let steps: [Step<'_>; 4] = [
        (
            "an endpoint is added",
            vec![
                FakeEndpoint::ready("10.0.0.1", "zone-a"),
                FakeEndpoint::ready("10.0.0.2", "zone-b"),
            ],
            vec!["10.0.0.1", "10.0.0.2"],
        ),
        (
            "an endpoint becomes not ready",
            vec![
                FakeEndpoint::ready("10.0.0.1", "zone-a"),
                FakeEndpoint::not_ready("10.0.0.2", "zone-b"),
            ],
            vec!["10.0.0.1"],
        ),
        (
            "an endpoint becomes terminating",
            vec![
                FakeEndpoint::terminating("10.0.0.1", "zone-a"),
                FakeEndpoint::not_ready("10.0.0.2", "zone-b"),
            ],
            vec![],
        ),
        (
            "an endpoint changes zone",
            vec![
                FakeEndpoint::ready("10.0.0.1", "zone-c"),
                FakeEndpoint::ready("10.0.0.2", "zone-b"),
            ],
            vec!["10.0.0.1", "10.0.0.2"],
        ),
    ];
    for (change, endpoints, expected) in steps {
        api.put_slice("user-service-a", &endpoints);

        let batch = watch.watch(&target(), &version).await.unwrap();

        assert_eq!(batch.changes.len(), 1, "{change}");
        version = batch.resource_version.clone();
        fold(&mut slices, batch);
        assert_eq!(offered(&slices), expected, "{change}");
    }
    let zone = slices["user-service-a"].first().unwrap().zone().unwrap();
    assert_eq!(zone.as_str(), "zone-c");
}

#[tokio::test]
async fn a_deleted_slice_leaves_the_watched_set() {
    let api = FakeKubernetesApi::start().await;
    api.put_slice(
        "user-service-a",
        &[FakeEndpoint::ready("10.0.0.1", "zone-a")],
    );
    let (watch, mut slices, version) = start(&api).await;

    api.delete_slice("user-service-a");
    let batch = watch.watch(&target(), &version).await.unwrap();
    fold(&mut slices, batch);

    assert_eq!(offered(&slices).len(), 0);
}

#[tokio::test]
async fn a_watch_without_events_ends_empty_and_keeps_the_version() {
    let api = FakeKubernetesApi::start().await;
    let (watch, _slices, version) = start(&api).await;

    let batch = watch.watch(&target(), &version).await.unwrap();

    assert_eq!(batch.changes.len(), 0);
    assert_eq!(batch.resource_version, version);
}

#[tokio::test]
async fn a_dropped_connection_resumes_from_the_last_version_without_losing_an_endpoint() {
    let api = FakeKubernetesApi::start().await;
    api.put_slice(
        "user-service-a",
        &[FakeEndpoint::ready("10.0.0.1", "zone-a")],
    );
    let (watch, mut slices, version) = start(&api).await;
    api.put_slice(
        "user-service-b",
        &[FakeEndpoint::ready("10.0.0.2", "zone-a")],
    );
    api.drop_next_watch();

    let dropped = watch.watch(&target(), &version).await;
    assert!(matches!(dropped, Err(EndpointWatchError::Unavailable(_))));
    let resumed = watch.watch(&target(), &version).await.unwrap();
    fold(&mut slices, resumed);

    assert_eq!(offered(&slices), ["10.0.0.1", "10.0.0.2"]);
    let watch_queries: Vec<_> = api
        .requests()
        .into_iter()
        .filter(|request| request.query.contains("watch=true"))
        .map(|request| {
            request
                .query
                .contains(&format!("resourceVersion={version}"))
        })
        .collect();
    assert_eq!(watch_queries, [true, true]);
}

#[tokio::test]
async fn a_410_expires_the_version_and_a_new_list_loses_nothing() {
    let api = FakeKubernetesApi::start().await;
    api.put_slice(
        "user-service-a",
        &[FakeEndpoint::ready("10.0.0.1", "zone-a")],
    );
    let (watch, _slices, version) = start(&api).await;
    api.put_slice(
        "user-service-b",
        &[FakeEndpoint::ready("10.0.0.2", "zone-a")],
    );
    api.put_slice(
        "user-service-a",
        &[FakeEndpoint::not_ready("10.0.0.1", "zone-a")],
    );
    api.compact();

    let expired = watch.watch(&target(), &version).await;
    assert!(matches!(expired, Err(EndpointWatchError::Expired)));
    let (_watch, relisted, new_version) = start(&api).await;

    assert_eq!(offered(&relisted), ["10.0.0.2"]);
    assert_eq!(new_version, api.version().to_string());
    api.put_slice(
        "user-service-c",
        &[FakeEndpoint::ready("10.0.0.3", "zone-a")],
    );
    let batch = watch.watch(&target(), &new_version).await.unwrap();
    assert_eq!(batch.changes.len(), 1);
}

#[tokio::test]
async fn an_error_event_with_code_410_in_the_stream_expires_the_version() {
    let api = FakeKubernetesApi::start().await;
    let (watch, _slices, version) = start(&api).await;
    api.gone_in_stream();

    let outcome = watch.watch(&target(), &version).await;

    assert!(matches!(outcome, Err(EndpointWatchError::Expired)));
}

#[tokio::test]
async fn a_list_body_that_breaks_or_is_no_slice_list_is_unavailable() {
    let api = FakeKubernetesApi::start().await;
    let watch = adapter(&api, None);

    api.answer_next(200, &["{\"kind\":"], true);
    let broken = watch.list(&target()).await;
    api.answer_next(200, &["not json"], false);
    let unparsable = watch.list(&target()).await;

    assert!(matches!(broken, Err(EndpointWatchError::Unavailable(_))));
    assert!(matches!(
        unparsable,
        Err(EndpointWatchError::Unavailable(_))
    ));
}

#[tokio::test]
async fn a_watch_line_split_over_frames_is_read_whole() {
    let api = FakeKubernetesApi::start().await;
    let (watch, mut slices, version) = start(&api).await;
    let line = serde_json::json!({
        "type": "ADDED",
        "object": {
            "metadata": {"name": "user-service-a", "resourceVersion": "9"},
            "addressType": "IPv4",
            "endpoints": [],
            "ports": [{"name": "http", "port": 8081, "protocol": "TCP"}]
        }
    })
    .to_string();
    let (head, tail) = line.split_at(10);
    let tail = format!("{tail}\n");

    api.answer_next(200, &[head, &tail], false);
    let batch = watch.watch(&target(), &version).await.unwrap();
    fold(&mut slices, batch.clone());

    assert_eq!(batch.resource_version, "9");
    assert!(slices.contains_key("user-service-a"));
}

#[tokio::test]
async fn a_watch_that_breaks_before_a_line_or_sends_no_event_is_unavailable() {
    let api = FakeKubernetesApi::start().await;
    let (watch, _slices, version) = start(&api).await;

    api.answer_next(200, &["{\"type\""], true);
    let broken = watch.watch(&target(), &version).await;
    api.answer_next(200, &["not json\n"], false);
    let unparsable = watch.watch(&target(), &version).await;

    assert!(matches!(broken, Err(EndpointWatchError::Unavailable(_))));
    assert!(matches!(
        unparsable,
        Err(EndpointWatchError::Unavailable(_))
    ));
}

#[tokio::test]
async fn an_error_event_with_another_code_in_the_stream_is_unavailable() {
    let api = FakeKubernetesApi::start().await;
    let (watch, _slices, version) = start(&api).await;
    let status = serde_json::json!({"kind": "Status", "code": 500, "reason": "InternalError"});
    let line = format!(
        "{}\n",
        serde_json::json!({"type": "ERROR", "object": status})
    );

    api.answer_next(200, &[&line], false);
    let outcome = watch.watch(&target(), &version).await;

    let Err(EndpointWatchError::Unavailable(error)) = outcome else {
        panic!("{outcome:?}");
    };
    assert!(error.to_string().contains("InternalError"), "{error}");
}

#[tokio::test]
async fn the_adapter_sends_only_get_requests_that_list_or_watch_endpointslices() {
    let api = FakeKubernetesApi::start().await;
    api.put_slice(
        "user-service-a",
        &[FakeEndpoint::ready("10.0.0.1", "zone-a")],
    );
    let (watch, _slices, version) = start(&api).await;
    api.put_slice(
        "user-service-a",
        &[FakeEndpoint::not_ready("10.0.0.1", "zone-a")],
    );
    watch.watch(&target(), &version).await.unwrap();

    let requests = api.requests();

    assert_eq!(requests.len(), 2);
    for request in &requests {
        assert_eq!(request.method, "GET");
        assert_eq!(
            request.path,
            "/apis/discovery.k8s.io/v1/namespaces/vilnacrm/endpointslices"
        );
        assert!(
            request
                .query
                .contains("labelSelector=kubernetes.io%2Fservice-name%3Duser-service")
        );
    }
    assert!(!requests.first().unwrap().query.contains("watch=true"));
    assert!(requests[1].query.contains("watch=true"));
}

#[tokio::test]
async fn the_serviceaccount_token_is_sent_as_a_bearer_token() {
    let api = FakeKubernetesApi::start().await;
    let token = TempFile::with("token", "secret-token\n");
    let watch = adapter(&api, Some(token.0.clone()));

    watch.list(&target()).await.unwrap();

    let requests = api.requests();
    let authorization = requests.first().unwrap().authorization.as_deref();
    assert_eq!(authorization, Some("Bearer secret-token"));
}

#[tokio::test]
async fn an_unreadable_token_file_is_an_unavailable_source() {
    let api = FakeKubernetesApi::start().await;
    let watch = adapter(&api, Some("/nonexistent/token".into()));

    let outcome = watch.list(&target()).await;

    assert!(matches!(outcome, Err(EndpointWatchError::Unavailable(_))));
    assert_eq!(api.requests().len(), 0);
}

#[tokio::test]
async fn a_target_that_is_not_a_dns_label_is_never_sent() {
    let api = FakeKubernetesApi::start().await;
    let watch = adapter(&api, None);
    let hostile = WatchTarget {
        namespace: "ns/../../secrets".to_owned(),
        service: "user-service".to_owned(),
    };

    let outcome = watch.list(&hostile).await;

    assert!(matches!(outcome, Err(EndpointWatchError::Unavailable(_))));
    assert_eq!(api.requests().len(), 0);
}

#[tokio::test]
async fn an_api_that_answers_an_error_status_is_an_unavailable_source() {
    let api = FakeKubernetesApi::start().await;
    api.fail_with(503);
    let watch = adapter(&api, None);

    let outcome = watch.list(&target()).await;

    assert!(matches!(outcome, Err(EndpointWatchError::Unavailable(_))));
}
