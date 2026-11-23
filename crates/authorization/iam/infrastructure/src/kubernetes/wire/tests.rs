use iam_domain::SliceChange;
use serde_json::json;

use super::{WatchEvent, batch, parse_event, parse_list};

fn slice_json(name: &str, version: &str, ready: bool, zone: &str) -> serde_json::Value {
    json!({
        "metadata": {"name": name, "resourceVersion": version},
        "addressType": "IPv4",
        "endpoints": [{
            "addresses": ["10.0.0.7"],
            "conditions": {"ready": ready, "serving": ready, "terminating": false},
            "zone": zone,
            "targetRef": {"kind": "Pod", "name": "user-service-0"}
        }],
        "ports": [{"name": "http", "port": 8081, "protocol": "TCP"}]
    })
}

fn line(kind: &str, object: &serde_json::Value) -> Vec<u8> {
    json!({"type": kind, "object": object})
        .to_string()
        .into_bytes()
}

#[test]
fn a_list_maps_every_slice_and_keeps_the_resource_version() {
    let body = json!({
        "metadata": {"resourceVersion": "42"},
        "items": [slice_json("user-service-abc", "40", true, "zone-a")]
    })
    .to_string();

    let listing = parse_list(body.as_bytes()).unwrap();

    assert_eq!(listing.resource_version, "42");
    let slice = listing.slices.first().unwrap();
    assert_eq!(slice.name, "user-service-abc");
    let endpoint = slice.endpoints.first().unwrap();
    assert_eq!(endpoint.address(), "10.0.0.7");
    assert_eq!(endpoint.port(), 8081);
    assert_eq!(
        endpoint.zone().map(iam_domain::Zone::as_str),
        Some("zone-a")
    );
    assert_eq!(endpoint.pod(), Some("user-service-0"));
    assert!(endpoint.is_offered());
}

#[test]
fn missing_conditions_mean_ready_and_serving_and_not_terminating() {
    let body = json!({
        "metadata": {"resourceVersion": "1"},
        "items": [{
            "metadata": {"name": "s"},
            "endpoints": [{"addresses": ["10.0.0.1", "10.0.0.2"]}],
            "ports": [{"port": 80}]
        }]
    })
    .to_string();

    let listing = parse_list(body.as_bytes()).unwrap();

    let endpoints = &listing.slices.first().unwrap().endpoints;
    assert_eq!(endpoints.len(), 2);
    assert!(endpoints.iter().all(|endpoint| {
        let conditions = endpoint.conditions();
        conditions.ready() && conditions.serving() && !conditions.terminating()
    }));
}

#[test]
fn a_slice_without_a_usable_port_has_no_endpoints() {
    let body = json!({
        "metadata": {"resourceVersion": "1"},
        "items": [
            {"metadata": {"name": "no-port"}, "endpoints": [{"addresses": ["10.0.0.1"]}]},
            {"metadata": {"name": "bad-port"}, "endpoints": [{"addresses": ["10.0.0.1"]}],
             "ports": [{"port": 70000}]}
        ]
    })
    .to_string();

    let listing = parse_list(body.as_bytes()).unwrap();

    assert!(
        listing
            .slices
            .iter()
            .all(|slice| slice.endpoints.is_empty())
    );
    assert_eq!(listing.slices.len(), 2);
}

#[test]
fn an_endpoint_with_an_invalid_zone_label_has_no_zone() {
    let body = json!({
        "metadata": {"resourceVersion": "1"},
        "items": [slice_json("s", "1", true, "not a zone")]
    })
    .to_string();

    let listing = parse_list(body.as_bytes()).unwrap();

    assert!(
        listing
            .slices
            .first()
            .unwrap()
            .endpoints
            .first()
            .unwrap()
            .zone()
            .is_none()
    );
}

#[test]
fn a_list_that_is_not_json_is_refused() {
    assert!(parse_list(b"<html>").is_err());
}

#[test]
fn added_and_modified_events_upsert_and_deleted_events_remove() {
    let object = slice_json("s1", "7", true, "zone-a");

    let added = parse_event(&line("ADDED", &object)).unwrap();
    let modified = parse_event(&line("MODIFIED", &object)).unwrap();
    let deleted = parse_event(&line("DELETED", &object)).unwrap();

    assert!(matches!(added, WatchEvent::Change(SliceChange::Upserted(_), ref v) if v == "7"));
    assert!(matches!(
        modified,
        WatchEvent::Change(SliceChange::Upserted(_), _)
    ));
    assert_eq!(
        deleted,
        WatchEvent::Change(SliceChange::Removed("s1".to_owned()), "7".to_owned())
    );
}

#[test]
fn a_bookmark_carries_only_the_version() {
    let object = json!({"metadata": {"resourceVersion": "99"}});

    assert_eq!(
        parse_event(&line("BOOKMARK", &object)).unwrap(),
        WatchEvent::Bookmark("99".to_owned())
    );
}

#[test]
fn an_error_event_with_code_410_means_the_version_is_gone() {
    let status = json!({"kind": "Status", "code": 410, "reason": "Expired"});

    assert_eq!(
        parse_event(&line("ERROR", &status)).unwrap(),
        WatchEvent::Gone
    );
}

#[test]
fn another_error_event_is_a_failure_without_the_message_of_the_api() {
    let status =
        json!({"kind": "Status", "code": 500, "reason": "InternalError", "message": "secret"});

    let event = parse_event(&line("ERROR", &status)).unwrap();

    assert_eq!(
        event,
        WatchEvent::Failed("the watch failed: InternalError".to_owned())
    );
}

#[test]
fn a_line_that_is_not_an_event_is_refused() {
    assert!(parse_event(b"not json").is_err());
}

#[test]
fn a_batch_collects_the_changes_and_resumes_from_the_last_version() {
    let events = vec![
        WatchEvent::Change(SliceChange::Removed("a".to_owned()), "8".to_owned()),
        WatchEvent::Bookmark("9".to_owned()),
        WatchEvent::Change(SliceChange::Removed("b".to_owned()), String::new()),
    ];

    let batch = batch("7", events).unwrap();

    assert_eq!(batch.resource_version, "9");
    assert_eq!(batch.changes.len(), 2);
}

#[test]
fn a_batch_without_events_keeps_the_resume_version() {
    let batch = batch("7", Vec::new()).unwrap();

    assert_eq!(batch.resource_version, "7");
    assert_eq!(batch.changes.len(), 0);
}

#[test]
fn a_batch_stops_at_a_gone_or_failed_event() {
    assert_eq!(batch("7", vec![WatchEvent::Gone]), Err(WatchEvent::Gone));
    let failed = WatchEvent::Failed("x".to_owned());
    assert_eq!(
        batch("7", vec![failed]),
        Err(WatchEvent::Failed("x".to_owned()))
    );
}
