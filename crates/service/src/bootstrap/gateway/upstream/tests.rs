use axum::http::header::{CONNECTION, CONTENT_LENGTH, HOST};
use axum::http::{HeaderName, HeaderValue};
use iam_application::{EndpointDirectory, ZoneSource};
use iam_domain::{
    EndpointConditions, EndpointParts, EndpointSlice, EnforcementMode, RetryPolicy, RouteDraft,
    RouteFields, RouteFlag, RouteFlags, RouteId, UpstreamId, UpstreamName, UpstreamSettings,
    UpstreamSettingsDraft, WatchTarget,
};
use shared_domain::Uuid;
use test_support::rng::FakeRng;

use super::*;

fn endpoint(address: &str, port: u16) -> UpstreamEndpoint {
    endpoint_with(address, port, EndpointConditions::healthy())
}

fn endpoint_with(address: &str, port: u16, conditions: EndpointConditions) -> UpstreamEndpoint {
    UpstreamEndpoint::new(EndpointParts {
        address: address.to_owned(),
        port,
        zone: None,
        pod: None,
        conditions,
    })
}

fn service() -> WatchTarget {
    WatchTarget {
        namespace: "vilnacrm".to_owned(),
        service: "user-service".to_owned(),
    }
}

fn target() -> UpstreamTarget {
    let settings = UpstreamSettings::new(&UpstreamSettingsDraft {
        namespace: "vilnacrm".to_owned(),
        service_name: "user-service".to_owned(),
        catalog_service: "user-service".to_owned(),
        port: 8080,
        protocol: UpstreamProtocol::Http1,
        forward_credentials: false,
        connect_timeout_ms: 250,
        response_timeout_ms: 10_000,
        concurrency_limit: 100,
        retry_budget_percent: 10,
        outlier_threshold: 5,
    })
    .unwrap();
    UpstreamTarget::new(
        UpstreamName::new("user-service").unwrap(),
        RouteId::from_uuid(Uuid::parse("00000000-0000-0000-0000-000000000001").unwrap()),
    )
    .with_settings(&settings)
}

fn route_fields(retry: RetryPolicy, graphql: bool) -> RouteFields {
    let flags = RouteFlags::default().with(RouteFlag::Graphql, graphql);
    RouteFields::new(&route_draft(flags, retry)).unwrap()
}

fn streaming_route() -> RouteFields {
    let flags = RouteFlags::default().with(RouteFlag::Streaming, true);
    RouteFields::new(&route_draft(flags, RetryPolicy::None)).unwrap()
}

fn route_draft(flags: RouteFlags, retry: RetryPolicy) -> RouteDraft {
    RouteDraft {
        host: "api.example.test".to_owned(),
        methods: vec![HttpMethod::Get],
        path_pattern: "/x".to_owned(),
        service: "core".to_owned(),
        upstream_id: UpstreamId::from_uuid(
            Uuid::parse("00000000-0000-0000-0000-000000000002").unwrap(),
        ),
        flags,
        enforcement: EnforcementMode::Enforce,
        body_limit: 1_048_576,
        request_timeout_ms: 2_500,
        idle_timeout_ms: 60_000,
        retry,
        rate_policies: Vec::new(),
        cors: None,
    }
}

fn forwarder_over(endpoints: Vec<UpstreamEndpoint>) -> HyperUpstreamForwarder {
    let directory = EndpointDirectory::new(ZoneSource {
        peers: WatchTarget {
            namespace: "vilnacrm".to_owned(),
            service: "iam-gateway-peers".to_owned(),
        },
        pod: None,
        explicit: None,
    });
    directory.replace(
        &service(),
        vec![EndpointSlice {
            name: "slice".to_owned(),
            endpoints,
        }],
    );
    HyperUpstreamForwarder::new(directory.view(), true, Arc::new(FakeRng::seeded(7)))
}

#[test]
fn a_declared_length_above_the_limit_is_refused_and_one_at_the_limit_is_not() {
    let mut headers = HeaderMap::new();
    assert!(!declared_above(&headers, 10));

    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("10"));
    assert!(!declared_above(&headers, 10));

    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("11"));
    assert!(declared_above(&headers, 10));

    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("many"));
    assert!(!declared_above(&headers, 10));
}

#[test]
fn the_absolute_target_holds_the_endpoint_the_path_and_the_query() {
    let uri: Uri = "/api/users?page=2".parse().unwrap();

    assert_eq!(
        absolute(&endpoint("10.0.0.7", 8080), &uri)
            .unwrap()
            .to_string(),
        "http://10.0.0.7:8080/api/users?page=2"
    );
    assert_eq!(
        absolute(&endpoint("fd00::7", 8080), &uri)
            .unwrap()
            .to_string(),
        "http://[fd00::7]:8080/api/users?page=2"
    );
}

#[test]
fn a_target_without_a_path_is_the_root() {
    let uri = Uri::from_static("http://gateway.example.test");

    assert_eq!(
        absolute(&endpoint("10.0.0.7", 80), &uri)
            .unwrap()
            .to_string(),
        "http://10.0.0.7:80/"
    );
}

#[test]
fn an_address_that_is_no_authority_gives_no_target() {
    assert_eq!(
        absolute(&endpoint("bad host", 80), &Uri::from_static("/x")),
        None
    );
}

#[test]
fn hop_by_hop_headers_and_the_headers_the_connection_names_are_removed() {
    let mut headers = HeaderMap::new();
    headers.insert(CONNECTION, HeaderValue::from_static("close, X-Hop"));
    headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
    headers.insert("proxy-authenticate", HeaderValue::from_static("Basic"));
    headers.insert("proxy-authorization", HeaderValue::from_static("Basic x"));
    headers.insert("te", HeaderValue::from_static("trailers"));
    headers.insert("trailer", HeaderValue::from_static("Expires"));
    headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
    headers.insert("upgrade", HeaderValue::from_static("websocket"));
    headers.insert("x-hop", HeaderValue::from_static("1"));
    headers.insert("x-kept", HeaderValue::from_static("2"));
    headers.insert(HOST, HeaderValue::from_static("api.example.test"));

    strip_hop_by_hop(&mut headers);

    let mut left: Vec<&str> = headers.keys().map(HeaderName::as_str).collect();
    left.sort_unstable();
    assert_eq!(left, ["host", "x-kept"]);
}

fn template_of(request: Request, target: &UpstreamTarget) -> Template {
    Template::of(request.into_parts().0, target)
}

#[test]
fn the_request_of_an_attempt_is_absolute_in_the_version_of_the_protocol() {
    let request = Request::builder()
        .uri("/api/users?a=1")
        .header(CONNECTION, "close")
        .header("x-kept", "yes")
        .body(Body::empty())
        .unwrap();
    let template = template_of(request, &target());

    let sent = template
        .request(&endpoint("10.0.0.7", 8080), Payload::Empty.body())
        .unwrap();

    assert_eq!(sent.uri().to_string(), "http://10.0.0.7:8080/api/users?a=1");
    assert_eq!(sent.version(), Version::HTTP_11);
    assert!(sent.headers().get(CONNECTION).is_none());
    assert_eq!(sent.headers().get("x-kept").unwrap(), "yes");
}

#[test]
fn the_template_keeps_the_method_and_serves_every_attempt() {
    let request = Request::builder()
        .method("PUT")
        .uri("/x")
        .body(Body::empty())
        .unwrap();
    let template = template_of(request, &target());

    for address in ["10.0.0.1", "10.0.0.2"] {
        let sent = template
            .request(&endpoint(address, 80), Payload::Empty.body())
            .unwrap();
        assert_eq!(sent.method(), Method::PUT);
        assert_eq!(sent.uri().host(), Some(address));
    }
}

#[test]
fn a_target_with_no_valid_address_cannot_be_built() {
    let request = Request::builder().uri("/x").body(Body::empty()).unwrap();
    let template = template_of(request, &target());

    let outcome = template.request(&endpoint("bad host", 80), Payload::Empty.body());

    assert_eq!(outcome.unwrap_err(), ForwardError::NoEndpoint);
}

#[test]
fn only_a_request_that_may_be_retried_after_it_was_sent_is_buffered() {
    let parts = |method: &str| {
        Request::builder()
            .method(method)
            .uri("/x")
            .body(Body::empty())
            .unwrap()
            .into_parts()
            .0
    };
    let idempotent = target().with_route(&route_fields(RetryPolicy::Idempotent, false));
    let none = target().with_route(&route_fields(RetryPolicy::None, false));
    let graphql = target().with_route(&route_fields(RetryPolicy::Idempotent, true));

    assert!(buffers(&idempotent, &parts("PUT")));
    assert!(buffers(&idempotent, &parts("GET")));
    assert!(!buffers(&idempotent, &parts("POST")));
    assert!(!buffers(&none, &parts("PUT")));
    assert!(buffers(&graphql, &parts("GET")));
    assert!(!buffers(&graphql, &parts("PUT")));
    assert!(!buffers(&idempotent, &parts("TRACE")));
}

#[tokio::test(start_paused = true)]
async fn the_deadline_is_the_request_timeout_of_the_route_and_none_for_a_streaming_route() {
    let ordinary = target().with_route(&route_fields(RetryPolicy::None, false));
    let before = Instant::now();

    let deadline = deadline_of(&ordinary).unwrap();

    assert_eq!(deadline - before, Duration::from_millis(2_500));
    assert_eq!(deadline_of(&target().with_route(&streaming_route())), None);
}

#[tokio::test(start_paused = true)]
async fn work_that_outlasts_the_deadline_fails_with_a_response_timeout() {
    let deadline = Instant::now().checked_add(Duration::from_secs(2));

    let outcome = within(deadline, tokio::time::sleep(Duration::from_secs(3))).await;

    assert_eq!(outcome.unwrap_err(), ForwardError::ResponseTimeout);
}

#[tokio::test(start_paused = true)]
async fn work_that_finishes_before_the_deadline_or_has_none_completes() {
    let deadline = Instant::now().checked_add(Duration::from_secs(2));

    assert!(
        within(deadline, async { 7 })
            .await
            .is_ok_and(|value| value == 7)
    );
    assert!(
        within(None, tokio::time::sleep(Duration::from_secs(3_600)))
            .await
            .is_ok()
    );
}

#[test]
fn the_requests_in_flight_are_counted_until_the_guard_drops() {
    let counts: InFlightCounts = Arc::default();
    let first = InFlight::enter(&counts, "a:1".to_owned());
    let second = InFlight::enter(&counts, "a:1".to_owned());
    let count = |key: &str| counts.lock().unwrap().get(key).copied();

    assert_eq!(count("a:1"), Some(2));
    drop(first);
    assert_eq!(count("a:1"), Some(1));
    drop(second);
    assert_eq!(count("a:1"), None);
}

#[test]
fn an_endpoint_is_keyed_by_address_and_port() {
    assert_eq!(endpoint_key(&endpoint("10.0.0.7", 8080)), "10.0.0.7:8080");
}

#[test]
fn a_service_without_endpoints_has_none_to_choose() {
    let forwarder = forwarder_over(Vec::new());

    assert_eq!(
        forwarder.choose(&target(), None).unwrap_err(),
        ForwardError::NoEndpoint
    );
}

#[test]
fn only_an_endpoint_that_is_ready_is_chosen() {
    let unready = endpoint_with("10.0.0.1", 80, EndpointConditions::default());
    let forwarder = forwarder_over(vec![unready.clone(), endpoint("10.0.0.2", 80)]);

    let chosen = forwarder.choose(&target(), None).unwrap();

    assert_eq!(chosen.address(), "10.0.0.2");
    assert_ne!(chosen, unready);
}

#[test]
fn the_choice_avoids_the_endpoint_with_more_requests_in_flight() {
    let forwarder = forwarder_over(vec![endpoint("10.0.0.1", 80), endpoint("10.0.0.2", 80)]);
    let _busy = InFlight::enter(&forwarder.in_flight, "10.0.0.1:80".to_owned());

    for _ in 0..20 {
        assert_eq!(
            forwarder.choose(&target(), None).unwrap().address(),
            "10.0.0.2"
        );
    }
}

#[test]
fn a_client_is_built_once_per_protocol_and_connect_timeout() {
    let forwarder = forwarder_over(Vec::new());

    drop(forwarder.client(&target()));
    drop(forwarder.client(&target()));

    assert_eq!(forwarder.clients.lock().unwrap().len(), 1);
}

type Connected = <HttpConnector as Service<Uri>>::Response;

/// A connector whose connection never completes.
#[derive(Debug, Clone, Copy)]
struct NeverConnects;

impl Service<Uri> for NeverConnects {
    type Response = Connected;
    type Error = ConnectError;
    type Future = std::future::Pending<Result<Connected, ConnectError>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), ConnectError>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        std::future::pending()
    }
}

#[tokio::test(start_paused = true)]
async fn a_connect_that_never_completes_fails_with_the_connect_timeout() {
    let mut connector = TimedConnector {
        inner: NeverConnects,
        timeout: Duration::from_millis(250),
    };

    let outcome = connector.call(Uri::from_static("http://10.0.0.7:80")).await;

    assert!(outcome.unwrap_err().is::<ConnectTimedOut>());
}

#[tokio::test(start_paused = true)]
async fn a_request_whose_connect_times_out_is_classified_as_a_connect_timeout() {
    let client: Client<_, ReplayBody> =
        Client::builder(TokioExecutor::new()).build(TimedConnector {
            inner: NeverConnects,
            timeout: Duration::from_millis(250),
        });
    let request = Request::builder()
        .uri("http://10.0.0.7:80/x")
        .body(Payload::Empty.body())
        .unwrap();

    let error = client.request(request).await.unwrap_err();

    let classified = classify(&error);
    assert_eq!(classified.error, ForwardError::ConnectTimeout);
    assert_eq!(classified.delivery, Delivery::NotSent);
    assert!(classified.connect);
}

#[tokio::test(start_paused = true)]
async fn an_error_of_the_inner_connector_passes_through_unchanged() {
    let mut connector = TimedConnector {
        inner: tower::service_fn(async |_uri: Uri| {
            Err::<Connected, ConnectError>("refused".into())
        }),
        timeout: Duration::from_millis(250),
    };

    let outcome = connector.call(Uri::from_static("http://10.0.0.7:80")).await;

    assert_eq!(outcome.unwrap_err().to_string(), "refused");
}

#[tokio::test]
async fn a_request_for_a_service_without_endpoints_is_refused_before_anything_is_sent() {
    let forwarder = forwarder_over(Vec::new());
    let request = Request::builder().uri("/x").body(Body::empty()).unwrap();

    let outcome = forwarder.forward(target(), request).await;

    assert_eq!(outcome.unwrap_err(), ForwardError::NoEndpoint);
}

#[tokio::test]
async fn an_endpoint_without_a_valid_address_is_refused_before_anything_is_sent() {
    let forwarder = forwarder_over(vec![endpoint("bad host", 80)]);
    let request = Request::builder().uri("/x").body(Body::empty()).unwrap();

    let outcome = forwarder.forward(target(), request).await;

    assert_eq!(outcome.unwrap_err(), ForwardError::NoEndpoint);
}
