use std::time::Duration;

use iam_domain::{EndpointConditions, EndpointParts, PolicyVersion, UpstreamEndpoint};

use super::{HyperPeerFreshnessClient, parse, peer_uri};

fn peer(address: &str, port: u16) -> UpstreamEndpoint {
    UpstreamEndpoint::new(EndpointParts {
        address: address.to_owned(),
        port,
        zone: None,
        pod: None,
        conditions: EndpointConditions::healthy(),
    })
}

#[test]
fn the_report_of_a_peer_is_read_from_its_address_and_port() {
    let uri = peer_uri(&peer("10.0.1.7", 9090)).unwrap();

    assert_eq!(uri.to_string(), "http://10.0.1.7:9090/internal/freshness");
}

#[test]
fn an_ipv6_address_is_put_in_brackets() {
    let uri = peer_uri(&peer("fd00::7", 9090)).unwrap();

    assert_eq!(uri.to_string(), "http://[fd00::7]:9090/internal/freshness");
}

#[test]
fn an_address_that_is_no_host_has_no_uri() {
    assert!(peer_uri(&peer("not a host", 9090)).is_none());
}

#[test]
fn a_full_report_is_read() {
    let observation =
        parse(br#"{"version":42,"digest":"ab","proofAgeMs":250,"hardBoundMs":15000,"fresh":true}"#)
            .unwrap();

    assert_eq!(observation.version, Some(PolicyVersion::new(42).unwrap()));
    assert!(observation.fresh);
    assert_eq!(observation.proof_age, Some(Duration::from_millis(250)));
}

#[test]
fn a_pod_without_a_snapshot_or_a_proof_reports_nulls() {
    let observation =
        parse(br#"{"version":null,"digest":null,"proofAgeMs":null,"hardBoundMs":1,"fresh":false}"#)
            .unwrap();

    assert_eq!(observation.version, None);
    assert!(!observation.fresh);
    assert_eq!(observation.proof_age, None);
}

#[test]
fn a_negative_version_is_left_out() {
    let observation = parse(br#"{"version":-1,"fresh":true}"#).unwrap();

    assert_eq!(observation.version, None);
}

#[test]
fn an_answer_that_is_not_a_report_is_unusable() {
    assert!(parse(b"<html></html>").is_none());
    assert!(parse(br#"{"version":1}"#).is_none());
}

#[test]
fn the_debug_form_names_the_client() {
    let client = HyperPeerFreshnessClient::default();

    assert!(format!("{client:?}").starts_with("HyperPeerFreshnessClient"));
}
