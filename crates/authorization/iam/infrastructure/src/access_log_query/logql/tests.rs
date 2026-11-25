use std::time::{Duration, SystemTime};

use iam_domain::{AccessDecision, AccessLogFilter, AccessLogRange, DecisionReason, SubjectKind};
use shared_domain::Uuid;

use super::{Labels, find_query, percent_encode, query_url, ready_url, search_query};

fn labels() -> Labels {
    Labels {
        app: "iam-gateway".to_owned(),
        env: "test".to_owned(),
    }
}

fn range() -> AccessLogRange {
    let from = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(100))
        .unwrap();
    let until = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(200))
        .unwrap();
    AccessLogRange::new(from, until, Duration::from_hours(1)).unwrap()
}

#[test]
fn an_empty_filter_selects_the_records_of_the_audit_lane_by_the_fixed_labels() {
    let query = search_query(&labels(), &AccessLogFilter::default());

    assert_eq!(
        query,
        r#"{app="iam-gateway",env="test",lane="audit",decision=~"allow|deny|error"}"#
    );
}

#[test]
fn the_decision_and_the_upstream_are_labels_of_the_selector() {
    let filter = AccessLogFilter {
        decision: Some(AccessDecision::Deny),
        upstream: Some("user-service".to_owned()),
        ..AccessLogFilter::default()
    };

    let query = search_query(&labels(), &filter);

    assert_eq!(
        query,
        r#"{app="iam-gateway",env="test",lane="audit",decision="deny",upstream="user-service"}"#
    );
}

#[test]
fn the_other_filters_are_structured_metadata_filters_in_a_fixed_order() {
    let route = Uuid::parse("0190f2a8-7b3c-7d4e-8f10-0000000000aa").unwrap();
    let filter = AccessLogFilter {
        subject_id: Some("user-1".to_owned()),
        subject_kind: Some(SubjectKind::User),
        reason: Some(DecisionReason::PermissionMissing),
        route_id: Some(route),
        status: Some(403),
        ..AccessLogFilter::default()
    };

    let query = search_query(&labels(), &filter);

    assert_eq!(
        query,
        format!(
            r#"{{app="iam-gateway",env="test",lane="audit",decision=~"allow|deny|error"}} | subject_id="user-1" | subject_kind="user" | reason="permission_missing" | route_id="{route}" | status="403""#
        )
    );
}

#[test]
fn a_value_is_written_as_a_logql_string_that_cannot_break_out() {
    let filter = AccessLogFilter {
        subject_id: Some("a\"b\\c\nd\re\tf".to_owned()),
        ..AccessLogFilter::default()
    };

    let query = search_query(&labels(), &filter);

    assert!(query.ends_with(r#" | subject_id="a\"b\\c\nd\re\tf""#));
}

#[test]
fn a_lookup_by_id_filters_on_the_decision_id_metadata() {
    let id = Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap();

    let query = find_query(&labels(), id);

    assert_eq!(
        query,
        r#"{app="iam-gateway",env="test",lane="audit",decision=~"allow|deny|error"} | decision_id="0190f2a8-7b3c-7d4e-8f10-1234567890ab""#
    );
}

#[test]
fn a_query_url_carries_the_range_the_limit_and_the_backward_direction() {
    let url = query_url("http://loki:3100/", "{a=\"b\"}", range(), 501);

    assert_eq!(
        url,
        "http://loki:3100/loki/api/v1/query_range?query=%7Ba%3D%22b%22%7D&start=100000000000&end=200000000000&limit=501&direction=backward"
    );
}

#[test]
fn the_ready_url_is_the_ready_endpoint_of_the_base() {
    assert_eq!(ready_url("http://loki:3100/"), "http://loki:3100/ready");
    assert_eq!(ready_url("http://loki:3100"), "http://loki:3100/ready");
}

#[test]
fn only_unreserved_characters_stay_unencoded() {
    assert_eq!(
        percent_encode("aZ09-_.~ |=\"é"),
        "aZ09-_.~%20%7C%3D%22%C3%A9"
    );
}
