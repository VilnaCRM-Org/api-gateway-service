use iam_domain::{
    EndpointConditions, EndpointParts, EndpointWatch as _, EndpointWatchError, SliceChange,
    UpstreamEndpoint, WatchTarget,
};

use super::FakeEndpointWatch;
use crate::block_on;

fn target(service: &str) -> WatchTarget {
    WatchTarget {
        namespace: "ns".to_owned(),
        service: service.to_owned(),
    }
}

fn endpoint(address: &str) -> UpstreamEndpoint {
    UpstreamEndpoint::new(EndpointParts {
        address: address.to_owned(),
        port: 80,
        zone: None,
        pod: None,
        conditions: EndpointConditions::healthy(),
    })
}

#[test]
fn a_list_returns_the_slices_of_the_target_at_the_current_version() {
    let watch = FakeEndpointWatch::new();
    watch.set_slice(&target("a"), "one", vec![endpoint("10.0.0.1")]);
    watch.set_slice(&target("b"), "two", vec![endpoint("10.0.0.2")]);

    let listing = block_on(watch.list(&target("a"))).unwrap();

    assert_eq!(listing.resource_version, "2");
    assert_eq!(listing.slices.len(), 1);
    assert_eq!(listing.slices.first().unwrap().name, "one");
    assert_eq!(watch.list_calls(), vec![target("a")]);
}

#[test]
fn a_watch_returns_only_the_events_of_its_target_after_the_version() {
    let watch = FakeEndpointWatch::new();
    watch.set_slice(&target("a"), "one", vec![endpoint("10.0.0.1")]);
    watch.set_slice(&target("b"), "two", vec![endpoint("10.0.0.2")]);
    watch.remove_slice(&target("a"), "one");

    let batch = block_on(watch.watch(&target("a"), "0")).unwrap();

    assert_eq!(batch.resource_version, "3");
    assert_eq!(batch.changes.len(), 2);
    assert!(matches!(batch.changes.get(1), Some(SliceChange::Removed(name)) if name == "one"));
    assert_eq!(watch.watch_calls(), vec![(target("a"), "0".to_owned())]);
}

#[test]
fn a_watch_without_news_keeps_its_version() {
    let watch = FakeEndpointWatch::new();

    let batch = block_on(watch.watch(&target("a"), "5")).unwrap();

    assert_eq!(batch.resource_version, "5");
    assert_eq!(batch.changes.len(), 0);
}

#[test]
fn an_expired_history_refuses_an_older_version() {
    let watch = FakeEndpointWatch::new();
    watch.set_slice(&target("a"), "one", vec![endpoint("10.0.0.1")]);
    watch.expire();

    assert!(matches!(
        block_on(watch.watch(&target("a"), "0")),
        Err(EndpointWatchError::Expired)
    ));
    assert!(block_on(watch.watch(&target("a"), "1")).is_ok());
}

#[test]
fn scheduled_failures_hit_the_next_calls_only() {
    let watch = FakeEndpointWatch::new();
    watch.fail_next(2);

    assert!(block_on(watch.list(&target("a"))).is_err());
    assert!(block_on(watch.watch(&target("a"), "0")).is_err());
    assert!(block_on(watch.list(&target("a"))).is_ok());
}

#[test]
fn a_version_that_is_not_a_number_is_an_unavailable_source() {
    let watch = FakeEndpointWatch::new();

    assert!(matches!(
        block_on(watch.watch(&target("a"), "x")),
        Err(EndpointWatchError::Unavailable(_))
    ));
}
