use iam_domain::SliceChange;
use serde_json::json;

use super::{WatchEvent, batch, parse_event, parse_list};

const MANAGED_BY: &str = "endpointslice.kubernetes.io/managed-by";
const MANAGER: &str = "endpointslice-controller.k8s.io";

fn slice_json(name: &str, version: &str, ready: bool, zone: &str) -> serde_json::Value {
    json!({
        "metadata": {
            "name": name,
            "resourceVersion": version,
            "labels": {"endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io"}
        },
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
            "metadata": {"name": "s", "labels": {
                "endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io"
            }},
            "addressType": "IPv4",
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
            {"metadata": {"name": "no-port", "labels": {MANAGED_BY: MANAGER}}, "addressType": "IPv4",
             "endpoints": [{"addresses": ["10.0.0.1"]}]},
            {"metadata": {"name": "bad-port", "labels": {MANAGED_BY: MANAGER}}, "addressType": "IPv4",
             "endpoints": [{"addresses": ["10.0.0.1"]}], "ports": [{"port": 70000}]}
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

/// The endpoints a one-slice list yields for a slice with `labels`, `address_type` and `addresses`.
fn mapped(
    labels: &serde_json::Value,
    address_type: &str,
    addresses: &[&str],
) -> Vec<iam_domain::UpstreamEndpoint> {
    let body = json!({
        "metadata": {"resourceVersion": "1"},
        "items": [{
            "metadata": {"name": "s", "labels": labels},
            "addressType": address_type,
            "endpoints": [{"addresses": addresses}],
            "ports": [{"port": 80}]
        }]
    })
    .to_string();
    parse_list(body.as_bytes())
        .unwrap()
        .slices
        .into_iter()
        .next()
        .unwrap()
        .endpoints
}

fn managed() -> serde_json::Value {
    json!({MANAGED_BY: MANAGER})
}

#[test]
fn a_slice_of_the_cluster_controller_is_mapped() {
    assert_eq!(mapped(&managed(), "IPv4", &["10.0.0.7"]).len(), 1);
    assert_eq!(mapped(&managed(), "IPv6", &["2001:db8::7"]).len(), 1);
}

#[test]
fn a_slice_without_the_managed_by_label_has_no_endpoints() {
    assert_eq!(mapped(&json!({}), "IPv4", &["10.0.0.7"]).len(), 0);
}

#[test]
fn a_slice_of_another_controller_has_no_endpoints() {
    let labels = json!({MANAGED_BY: "tenant-controller.example.com"});

    assert_eq!(mapped(&labels, "IPv4", &["10.0.0.7"]).len(), 0);
}

#[test]
fn a_slice_whose_address_type_is_not_ip_has_no_endpoints() {
    assert_eq!(mapped(&managed(), "FQDN", &["evil.example.com"]).len(), 0);
    assert_eq!(mapped(&managed(), "", &["10.0.0.7"]).len(), 0);
    assert_eq!(mapped(&managed(), "ipv4", &["10.0.0.7"]).len(), 0);
}

#[test]
fn an_address_that_is_a_host_name_is_refused() {
    assert_eq!(mapped(&managed(), "IPv4", &["evil.example.com"]).len(), 0);
    assert_eq!(mapped(&managed(), "IPv6", &["localhost"]).len(), 0);
}

#[test]
fn an_address_of_the_other_family_is_refused() {
    assert_eq!(mapped(&managed(), "IPv4", &["2001:db8::7"]).len(), 0);
    assert_eq!(mapped(&managed(), "IPv6", &["10.0.0.7"]).len(), 0);
}

#[rstest::rstest]
#[case::v4_loopback("IPv4", "127.0.0.1")]
#[case::v4_loopback_range("IPv4", "127.9.9.9")]
#[case::v4_link_local("IPv4", "169.254.169.254")]
#[case::v4_unspecified("IPv4", "0.0.0.0")]
#[case::v4_multicast("IPv4", "224.0.0.1")]
#[case::v6_loopback("IPv6", "::1")]
#[case::v6_link_local("IPv6", "fe80::1")]
#[case::v6_unspecified("IPv6", "::")]
#[case::v6_multicast("IPv6", "ff02::1")]
#[case::v6_mapped_loopback("IPv6", "::ffff:127.0.0.1")]
fn an_address_that_is_not_a_unicast_upstream_is_refused(
    #[case] address_type: &str,
    #[case] address: &str,
) {
    assert_eq!(mapped(&managed(), address_type, &[address]).len(), 0);
}

#[test]
fn a_refused_address_leaves_the_other_addresses_of_the_endpoint() {
    let endpoints = mapped(&managed(), "IPv4", &["127.0.0.1", "10.0.0.8", ""]);

    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints.first().unwrap().address(), "10.0.0.8");
}
