use std::error::Error as _;

use super::{EndpointWatchError, WatchTarget};

fn target() -> WatchTarget {
    WatchTarget {
        namespace: "vilnacrm".to_owned(),
        service: "user-service".to_owned(),
    }
}

#[test]
fn the_fallback_name_is_fully_qualified_with_a_trailing_dot() {
    assert_eq!(
        target().fully_qualified_name(),
        "user-service.vilnacrm.svc.cluster.local."
    );
}

#[test]
fn a_target_displays_its_namespace_and_service() {
    assert_eq!(target().to_string(), "vilnacrm/user-service");
}

#[test]
fn an_expired_watch_has_no_source() {
    let error = EndpointWatchError::Expired;

    assert_eq!(error.to_string(), "the watch resource version expired");
    assert!(error.source().is_none());
}

#[test]
fn an_unavailable_source_chains_its_cause() {
    let error = EndpointWatchError::Unavailable("connection reset".into());

    assert_eq!(error.to_string(), "the endpoint source is unavailable");
    assert_eq!(error.source().unwrap().to_string(), "connection reset");
}
