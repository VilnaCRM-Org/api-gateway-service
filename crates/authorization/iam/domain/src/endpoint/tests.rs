use rstest::rstest;

use super::zone::Zone;
use super::{Condition, EndpointConditions, EndpointParts, UpstreamEndpoint};

fn endpoint(conditions: EndpointConditions) -> UpstreamEndpoint {
    UpstreamEndpoint::new(EndpointParts {
        address: "10.0.0.7".to_owned(),
        port: 8081,
        zone: Some(Zone::new("zone-a").unwrap()),
        pod: Some("user-service-0".to_owned()),
        conditions,
    })
}

#[test]
fn an_endpoint_reports_its_parts() {
    let endpoint = endpoint(EndpointConditions::healthy());

    assert_eq!(endpoint.address(), "10.0.0.7");
    assert_eq!(endpoint.port(), 8081);
    assert_eq!(endpoint.zone().map(Zone::as_str), Some("zone-a"));
    assert_eq!(endpoint.pod(), Some("user-service-0"));
    assert_eq!(endpoint.conditions(), EndpointConditions::healthy());
}

#[test]
fn conditions_start_off_and_switch_independently() {
    let none = EndpointConditions::default();
    assert!(!none.ready() && !none.serving() && !none.terminating());

    let ready = none.with(Condition::Ready, true);
    assert!(ready.ready() && !ready.serving() && !ready.terminating());

    let terminating = ready
        .with(Condition::Terminating, true)
        .with(Condition::Serving, true);
    assert!(terminating.ready() && terminating.serving() && terminating.terminating());

    assert!(!terminating.with(Condition::Ready, false).ready());
    assert!(terminating.has(Condition::Terminating));
}

#[rstest]
#[case(EndpointConditions::healthy(), true)]
#[case(EndpointConditions::default(), false)]
#[case(EndpointConditions::healthy().with(Condition::Ready, false), false)]
#[case(EndpointConditions::healthy().with(Condition::Terminating, true), false)]
fn only_a_ready_endpoint_that_is_not_terminating_is_offered(
    #[case] conditions: EndpointConditions,
    #[case] offered: bool,
) {
    assert_eq!(endpoint(conditions).is_offered(), offered);
}

#[test]
fn an_endpoint_without_a_zone_or_pod_reports_none() {
    let endpoint = UpstreamEndpoint::new(EndpointParts {
        address: "svc.ns.svc.cluster.local.".to_owned(),
        port: 80,
        zone: None,
        pod: None,
        conditions: EndpointConditions::healthy(),
    });

    assert!(endpoint.zone().is_none());
    assert!(endpoint.pod().is_none());
}
