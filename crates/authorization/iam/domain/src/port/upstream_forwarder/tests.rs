use shared_domain::Uuid;

use super::*;

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
            "the upstream failed",
        ]
    );
}
