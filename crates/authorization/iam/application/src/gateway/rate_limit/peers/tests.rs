use iam_domain::{
    Condition, EndpointConditions, EndpointParts, EndpointSlice, ReadyPeers as _, UpstreamEndpoint,
    WatchTarget,
};

use super::EndpointReadyPeers;
use crate::{EndpointDirectory, ZoneSource};

fn target() -> WatchTarget {
    WatchTarget {
        namespace: "vilnacrm".to_owned(),
        service: "iam-gateway-peers".to_owned(),
    }
}

fn endpoint(pod: &str, conditions: EndpointConditions) -> UpstreamEndpoint {
    UpstreamEndpoint::new(EndpointParts {
        address: format!("10.0.0.{}", pod.len()),
        port: 8081,
        zone: None,
        pod: Some(pod.to_owned()),
        conditions,
    })
}

fn directory() -> EndpointDirectory {
    EndpointDirectory::new(ZoneSource {
        peers: target(),
        pod: None,
        explicit: None,
    })
}

#[test]
fn no_known_endpoint_is_no_ready_peer() {
    let peers = EndpointReadyPeers::new(directory().view(), target());

    assert_eq!(peers.ready_endpoints(), 0);
}

#[test]
fn only_the_endpoints_a_request_may_go_to_count() {
    let directory = directory();
    let peers = EndpointReadyPeers::new(directory.view(), target());
    let healthy = EndpointConditions::healthy();
    directory.replace(
        &target(),
        vec![EndpointSlice {
            name: "a".to_owned(),
            endpoints: vec![
                endpoint("p1", healthy),
                endpoint("p22", healthy),
                endpoint("p333", healthy),
                endpoint("p4444", healthy.with(Condition::Ready, false)),
            ],
        }],
    );

    assert_eq!(peers.ready_endpoints(), 3);
}
