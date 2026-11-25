use shared_domain::Uuid;

use super::*;
use crate::upstream::settings::UpstreamSettingsDraft;

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
}
