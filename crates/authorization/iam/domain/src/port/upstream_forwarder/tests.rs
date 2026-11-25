use shared_domain::Uuid;

use super::*;
use crate::route::fixtures;
use crate::route::settings::RouteFlag;
use crate::upstream::settings::UpstreamSettingsDraft;
use crate::value_object::http_method::HttpMethod;

fn route_uuid() -> Uuid {
    Uuid::parse("00000000-0000-0000-0000-000000000007").unwrap()
}

fn target() -> UpstreamTarget {
    UpstreamTarget::new(
        UpstreamName::new("user-service").unwrap(),
        RouteId::from_uuid(route_uuid()),
    )
}

#[test]
fn a_target_names_its_upstream_and_its_route() {
    let target = target();

    assert_eq!(target.upstream().as_str(), "user-service");
    assert_eq!(target.route(), RouteId::from_uuid(route_uuid()));
}

#[test]
fn every_forward_error_says_what_went_wrong() {
    let texts: Vec<String> = [
        ForwardError::NotSent,
        ForwardError::ConnectTimeout,
        ForwardError::ResponseTimeout,
        ForwardError::Overloaded,
        ForwardError::NoEndpoint,
        ForwardError::BodyTooLarge,
        ForwardError::Upstream,
    ]
    .iter()
    .map(ToString::to_string)
    .collect();

    assert_eq!(
        texts,
        [
            "the request was not sent to an upstream endpoint",
            "the connection to the upstream timed out",
            "the upstream did not answer in time",
            "the upstream is overloaded",
            "the upstream has no endpoint",
            "the request body is above the limit of the route",
            "the upstream failed",
        ]
    );
}

#[test]
fn a_target_without_settings_has_the_defaults_and_no_service() {
    let target = target();

    assert_eq!(target.service().namespace, "");
    assert_eq!(target.service().service, "");
    assert_eq!(target.protocol(), UpstreamProtocol::Http1);
    assert_eq!(target.connect_timeout_ms(), 250);
    assert_eq!(target.response_timeout_ms(), 10_000);
    assert_eq!(target.body_limit(), 10 * 1024 * 1024);
    assert!(!target.forward_credentials());
}

#[test]
fn a_target_takes_its_delivery_from_the_upstream_settings_and_its_limit_from_the_route() {
    let settings = UpstreamSettings::new(&UpstreamSettingsDraft {
        namespace: "vilnacrm".to_owned(),
        service_name: "user-service".to_owned(),
        catalog_service: "user-service".to_owned(),
        port: 8080,
        protocol: UpstreamProtocol::H2c,
        forward_credentials: true,
        connect_timeout_ms: 300,
        response_timeout_ms: 4_000,
        concurrency_limit: 10,
        retry_budget_percent: 10,
        outlier_threshold: 5,
    })
    .unwrap();

    let target = target()
        .with_settings(&settings)
        .with_body_limit(BodyLimit::new(2_048).unwrap());

    assert_eq!(target.service().namespace, "vilnacrm");
    assert_eq!(target.service().service, "user-service");
    assert_eq!(target.protocol(), UpstreamProtocol::H2c);
    assert_eq!(target.connect_timeout_ms(), 300);
    assert_eq!(target.response_timeout_ms(), 4_000);
    assert_eq!(target.body_limit(), 2_048);
    assert!(target.forward_credentials());
}

fn route_fields(flags: RouteFlags, retry: RetryPolicy, request_timeout_ms: i64) -> RouteFields {
    let mut draft = fixtures::draft("api.example.test", "/api/users", &[HttpMethod::Get]);
    draft.flags = flags;
    draft.retry = retry;
    draft.request_timeout_ms = request_timeout_ms;
    RouteFields::new(&draft).unwrap()
}

fn settings_with(response_timeout_ms: i64) -> UpstreamSettings {
    UpstreamSettings::new(&UpstreamSettingsDraft {
        namespace: "vilnacrm".to_owned(),
        service_name: "user-service".to_owned(),
        catalog_service: "user-service".to_owned(),
        port: 8080,
        protocol: UpstreamProtocol::Http1,
        forward_credentials: false,
        connect_timeout_ms: 250,
        response_timeout_ms,
        concurrency_limit: 2,
        retry_budget_percent: 25,
        outlier_threshold: 3,
    })
    .unwrap()
}

#[test]
fn a_target_without_a_route_or_settings_has_the_resilience_defaults() {
    let target = target();

    assert_eq!(target.headers_timeout_ms(), 10_000);
    assert_eq!(target.request_timeout_ms(), Some(60_000));
    assert!(!target.graphql());
    assert_eq!(target.retry(), RetryPolicy::None);
    assert_eq!(target.concurrency_limit(), u32::MAX);
    assert_eq!(target.retry_budget_percent(), 10);
    assert_eq!(target.outlier_threshold(), 5);
}

#[test]
fn the_settings_of_the_upstream_set_the_limits_of_the_target() {
    let target = target().with_settings(&settings_with(4_000));

    assert_eq!(target.concurrency_limit(), 2);
    assert_eq!(target.retry_budget_percent(), 25);
    assert_eq!(target.outlier_threshold(), 3);
    assert_eq!(target.headers_timeout_ms(), 4_000);
}

#[test]
fn the_route_sets_the_retry_policy_the_request_timeout_and_the_body_limit() {
    let fields = route_fields(RouteFlags::default(), RetryPolicy::Idempotent, 2_500);

    let target = target().with_route(&fields);

    assert_eq!(target.retry(), RetryPolicy::Idempotent);
    assert_eq!(target.request_timeout_ms(), Some(2_500));
    assert_eq!(target.body_limit(), 1_048_576);
    assert!(!target.graphql());
}

#[test]
fn a_streaming_route_has_no_request_timeout() {
    let flags = RouteFlags::default().with(RouteFlag::Streaming, true);

    let target = target().with_route(&route_fields(flags, RetryPolicy::None, 30_000));

    assert_eq!(target.request_timeout_ms(), None);
}

#[test]
fn a_graphql_route_waits_thirty_seconds_for_headers_unless_its_upstream_overrides_the_default() {
    let flags = RouteFlags::default().with(RouteFlag::Graphql, true);
    let graphql = target().with_route(&route_fields(flags, RetryPolicy::None, 60_000));

    assert!(graphql.graphql());
    assert_eq!(graphql.headers_timeout_ms(), 30_000);
    assert_eq!(
        graphql
            .clone()
            .with_settings(&settings_with(10_000))
            .headers_timeout_ms(),
        30_000
    );
    assert_eq!(
        graphql
            .with_settings(&settings_with(4_000))
            .headers_timeout_ms(),
        4_000
    );
}
