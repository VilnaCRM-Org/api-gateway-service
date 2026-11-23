use iam_domain::{
    EndpointConditions, EndpointParts, EndpointSlice, SliceChange, UpstreamEndpoint, WatchTarget,
    Zone,
};

use super::{EndpointDirectory, ZoneSource};

fn target(service: &str) -> WatchTarget {
    WatchTarget {
        namespace: "vilnacrm".to_owned(),
        service: service.to_owned(),
    }
}

fn endpoint(
    address: &str,
    zone: &str,
    pod: &str,
    conditions: EndpointConditions,
) -> UpstreamEndpoint {
    UpstreamEndpoint::new(EndpointParts {
        address: address.to_owned(),
        port: 8081,
        zone: Some(Zone::new(zone).unwrap()),
        pod: Some(pod.to_owned()),
        conditions,
    })
}

fn slice(name: &str, endpoints: Vec<UpstreamEndpoint>) -> EndpointSlice {
    EndpointSlice {
        name: name.to_owned(),
        endpoints,
    }
}

fn directory(pod: Option<&str>, explicit: Option<&str>) -> EndpointDirectory {
    EndpointDirectory::new(ZoneSource {
        peers: target("iam-gateway-peers"),
        pod: pod.map(str::to_owned),
        explicit: explicit.map(|zone| Zone::new(zone).unwrap()),
    })
}

#[test]
fn an_unknown_service_has_no_endpoints() {
    let view = directory(None, None).view();

    assert_eq!(view.endpoints(&target("user-service")).len(), 0);
    assert_eq!(view.offered(&target("user-service")).len(), 0);
}

#[test]
fn a_replace_sets_every_slice_and_drops_the_old_ones() {
    let directory = directory(None, None);
    let view = directory.view();
    let healthy = EndpointConditions::healthy();
    directory.replace(
        &target("user-service"),
        vec![
            slice("a", vec![endpoint("10.0.0.1", "z1", "p1", healthy)]),
            slice("b", vec![endpoint("10.0.0.2", "z1", "p2", healthy)]),
        ],
    );
    assert_eq!(view.endpoints(&target("user-service")).len(), 2);

    directory.replace(
        &target("user-service"),
        vec![slice("c", vec![endpoint("10.0.0.3", "z1", "p3", healthy)])],
    );

    let addresses: Vec<_> = view
        .endpoints(&target("user-service"))
        .iter()
        .map(|endpoint| endpoint.address().to_owned())
        .collect();
    assert_eq!(addresses, ["10.0.0.3"]);
}

#[test]
fn a_change_upserts_or_removes_a_slice_and_only_offered_endpoints_are_offered() {
    let directory = directory(None, None);
    let view = directory.view();
    let healthy = EndpointConditions::healthy();
    let terminating = healthy.with(iam_domain::Condition::Terminating, true);

    directory.apply(
        &target("user-service"),
        SliceChange::Upserted(slice(
            "a",
            vec![
                endpoint("10.0.0.1", "z1", "p1", healthy),
                endpoint("10.0.0.2", "z1", "p2", terminating),
                endpoint("10.0.0.3", "z1", "p3", EndpointConditions::default()),
            ],
        )),
    );

    assert_eq!(view.endpoints(&target("user-service")).len(), 3);
    assert_eq!(view.offered(&target("user-service")).len(), 1);

    directory.apply(
        &target("user-service"),
        SliceChange::Removed("a".to_owned()),
    );
    assert_eq!(view.endpoints(&target("user-service")).len(), 0);
}

#[test]
fn the_zone_is_taken_from_the_own_entry_in_the_peers_slices() {
    let directory = directory(Some("gateway-1"), None);
    let view = directory.view();
    assert_eq!(view.own_zone(), None);

    let healthy = EndpointConditions::healthy();
    directory.replace(
        &target("iam-gateway-peers"),
        vec![slice(
            "peers",
            vec![
                endpoint("10.0.9.1", "zone-a", "gateway-0", healthy),
                endpoint("10.0.9.2", "zone-b", "gateway-1", healthy),
            ],
        )],
    );

    assert_eq!(view.own_zone(), Some(Zone::new("zone-b").unwrap()));
}

#[test]
fn an_explicit_zone_overrides_the_peers_slices() {
    let directory = directory(Some("gateway-1"), Some("zone-x"));
    let view = directory.view();
    directory.replace(
        &target("iam-gateway-peers"),
        vec![slice(
            "peers",
            vec![endpoint(
                "10.0.9.2",
                "zone-b",
                "gateway-1",
                EndpointConditions::healthy(),
            )],
        )],
    );

    assert_eq!(view.own_zone(), Some(Zone::new("zone-x").unwrap()));
}

#[test]
fn without_a_pod_name_and_an_explicit_zone_the_zone_is_unknown() {
    let directory = directory(None, None);
    directory.replace(
        &target("iam-gateway-peers"),
        vec![slice(
            "peers",
            vec![endpoint(
                "10.0.9.2",
                "zone-b",
                "gateway-1",
                EndpointConditions::healthy(),
            )],
        )],
    );

    assert_eq!(directory.view().own_zone(), None);
}

#[tokio::test]
async fn a_view_wakes_when_the_directory_changes_and_ends_when_it_is_gone() {
    let directory = directory(None, None);
    let mut view = directory.view();

    directory.replace(&target("user-service"), Vec::new());
    assert!(view.changed().await);

    drop(directory);
    assert!(!view.changed().await);
}
