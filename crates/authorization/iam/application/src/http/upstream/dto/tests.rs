use iam_domain::{EntityVersion, UpstreamId, UpstreamProtocol};
use rstest::rstest;
use serde_json::json;
use validator::Validate as _;

use super::{
    CreateUpstreamRequest, ListUpstreamsParams, UpdateUpstreamRequest, UpstreamPageResponse,
    UpstreamProtocolDto, UpstreamResponse, delete_upstream_canonical_form,
};
use crate::error::IamError;
use crate::query::list_upstreams::UpstreamPage;
use crate::upstream_fixtures::{UPSTREAM, upstream, upstream_id};

fn create_request() -> CreateUpstreamRequest {
    serde_json::from_value(json!({
        "name": "core",
        "namespace": "platform",
        "service": "core-service",
        "catalogService": "core",
        "port": 8080,
        "protocol": "h2c",
    }))
    .unwrap()
}

#[rstest]
#[case(UpstreamProtocolDto::Http1, UpstreamProtocol::Http1)]
#[case(UpstreamProtocolDto::H2c, UpstreamProtocol::H2c)]
fn the_wire_protocol_and_the_domain_protocol_convert_both_ways(
    #[case] wire: UpstreamProtocolDto,
    #[case] domain: UpstreamProtocol,
) {
    assert_eq!(UpstreamProtocol::from(wire), domain);
    assert_eq!(UpstreamProtocolDto::from(domain), wire);
}

#[test]
fn a_creation_without_the_optional_members_takes_the_defaults() {
    let request = create_request();

    assert!(!request.forward_credentials);
    assert_eq!(request.connect_timeout_ms, 250);
    assert_eq!(request.response_timeout_ms, 10_000);
    assert_eq!(request.concurrency_limit, 256);
    assert_eq!(request.retry_budget_percent, 10);
    assert_eq!(request.outlier_consecutive_errors, 5);
    assert!(request.validate().is_ok());
}

#[test]
fn the_canonical_form_of_a_creation_changes_with_every_field() {
    let first = create_request();
    let mut second = create_request();
    second.port = 8081;

    assert!(first.canonical_form().starts_with("upstream.create:"));
    assert_ne!(first.canonical_form(), second.canonical_form());
    assert_eq!(first.canonical_form(), create_request().canonical_form());
}

#[test]
fn the_canonical_forms_of_an_update_and_a_deletion_name_the_upstream_and_the_version() {
    let request = UpdateUpstreamRequest {
        port: Some(9090),
        ..UpdateUpstreamRequest::default()
    };
    let version_one = EntityVersion::new(1).unwrap();
    let version_two = EntityVersion::new(2).unwrap();
    let other = UpstreamId::parse("0190f2a8-7b3c-7d4e-8f10-1234567890d1").unwrap();

    let update = request.canonical_form(upstream_id(), version_one);

    assert!(update.starts_with("upstream.update:"));
    assert!(update.contains(UPSTREAM));
    assert_ne!(update, request.canonical_form(upstream_id(), version_two));
    assert_ne!(update, request.canonical_form(other, version_one));
    let deletion = delete_upstream_canonical_form(upstream_id(), version_one);
    assert!(deletion.starts_with("upstream.delete:"));
    assert_ne!(
        deletion,
        delete_upstream_canonical_form(upstream_id(), version_two)
    );
    assert_ne!(deletion, delete_upstream_canonical_form(other, version_one));
    assert_ne!(deletion, update);
}

#[test]
fn an_update_with_every_member_becomes_a_patch_with_every_member() {
    let request: UpdateUpstreamRequest = serde_json::from_value(json!({
        "name": "core",
        "namespace": "edge",
        "service": "core-v2",
        "catalogService": "payment",
        "forwardCredentials": true,
        "port": 9090,
        "protocol": "http1",
        "connectTimeoutMs": 500,
        "responseTimeoutMs": 20_000,
        "concurrencyLimit": 64,
        "retryBudgetPercent": 25,
        "outlierConsecutiveErrors": 3,
    }))
    .unwrap();

    let patch = request.into_patch();

    assert_eq!(patch.name.as_deref(), Some("core"));
    assert_eq!(patch.namespace.as_deref(), Some("edge"));
    assert_eq!(patch.service_name.as_deref(), Some("core-v2"));
    assert_eq!(patch.catalog_service.as_deref(), Some("payment"));
    assert_eq!(patch.forward_credentials, Some(true));
    assert_eq!(patch.port, Some(9090));
    assert_eq!(patch.protocol, Some(UpstreamProtocol::Http1));
    assert_eq!(patch.connect_timeout_ms, Some(500));
    assert_eq!(patch.response_timeout_ms, Some(20_000));
    assert_eq!(patch.concurrency_limit, Some(64));
    assert_eq!(patch.retry_budget_percent, Some(25));
    assert_eq!(patch.outlier_threshold, Some(3));
}

#[test]
fn an_empty_update_is_an_empty_patch() {
    let request: UpdateUpstreamRequest = serde_json::from_value(json!({})).unwrap();

    assert_eq!(request.into_patch(), crate::UpstreamPatch::default());
}

#[test]
fn an_update_validates_the_length_of_the_names_it_carries() {
    let request = UpdateUpstreamRequest {
        namespace: Some(String::new()),
        ..UpdateUpstreamRequest::default()
    };

    assert!(request.validate().is_err());
    assert!(UpdateUpstreamRequest::default().validate().is_ok());
}

#[test]
fn a_stored_upstream_is_shown_with_every_field_in_the_names_of_the_wire() {
    let response = UpstreamResponse::from(upstream(3));

    assert_eq!(
        serde_json::to_value(&response).unwrap(),
        json!({
            "id": UPSTREAM,
            "name": "core",
            "namespace": "platform",
            "service": "core-service",
            "catalogService": "core",
            "forwardCredentials": false,
            "port": 8080,
            "protocol": "h2c",
            "connectTimeoutMs": 250,
            "responseTimeoutMs": 10_000,
            "concurrencyLimit": 256,
            "retryBudgetPercent": 10,
            "outlierConsecutiveErrors": 5,
            "system": false,
            "version": 3,
            "createdAt": "2027-01-15T08:00:00.000000Z",
            "updatedAt": "2027-01-15T08:05:00.000000Z",
        })
    );
}

#[test]
fn a_page_lists_its_items_and_names_the_cursor_only_when_another_page_follows() {
    let last = UpstreamPageResponse::from(UpstreamPage {
        upstreams: vec![upstream(1)],
        next_after: None,
    });
    let more = UpstreamPageResponse::from(UpstreamPage {
        upstreams: vec![upstream(1)],
        next_after: Some(upstream_id()),
    });

    assert_eq!(last.items.len(), 1);
    assert_eq!(last.next_cursor, None);
    assert_eq!(more.next_cursor.as_deref(), Some(UPSTREAM));
    assert_eq!(serde_json::to_value(&last).unwrap().get("nextCursor"), None);
}

#[test]
fn the_parameters_default_to_the_first_page_of_30() {
    let params = ListUpstreamsParams::default();

    assert_eq!(params.limit, 30);
    assert_eq!(params.after, None);
    assert!(params.validate().is_ok());
}

#[rstest]
#[case(0)]
#[case(-3)]
#[case(101)]
fn a_limit_outside_1_to_100_is_invalid(#[case] limit: i32) {
    let params = ListUpstreamsParams { limit, after: None };

    assert!(params.validate().is_err());
}

#[test]
fn valid_parameters_become_the_query_with_its_cursor() {
    let query = ListUpstreamsParams {
        limit: 7,
        after: Some(UPSTREAM.to_owned()),
    }
    .into_query()
    .unwrap();

    assert_eq!(query.limit, 7);
    assert_eq!(query.after, Some(upstream_id()));
}

#[test]
fn a_cursor_that_is_not_a_uuid_is_a_violation_of_after() {
    let error = ListUpstreamsParams {
        limit: 7,
        after: Some("nope".to_owned()),
    }
    .into_query()
    .unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("a violation expected: {error:?}");
    };
    assert_eq!(violations[0].property_path, "after");
    assert_eq!(violations[0].code, "uuid");
}
