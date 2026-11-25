use std::time::{Duration, SystemTime};

use iam_domain::{AccessDecision, AccessLogCursor, DecisionReason, SubjectKind};
use rstest::rstest;
use shared_domain::Uuid;

use super::{AccessDecisionPageResponse, AccessDecisionResponse, ListAccessDecisionsParams};
use crate::access_decision_fixtures::{decision_id, entry};
use crate::error::IamError;
use crate::query::get_access_decisions::AccessDecisionPage;
use crate::security_audit_fixtures::actor;

fn window() -> ListAccessDecisionsParams {
    ListAccessDecisionsParams {
        from: Some("2026-11-23T08:00:00Z".to_owned()),
        until: Some("2026-11-23T09:00:00Z".to_owned()),
        ..ListAccessDecisionsParams::default()
    }
}

fn property_of(error: IamError) -> String {
    let IamError::Invalid(violations) = error else {
        panic!("expected a violation");
    };
    violations[0].property_path.clone()
}

#[test]
fn a_decision_is_shown_without_the_digest_of_the_credential() {
    let shown = AccessDecisionResponse::from(&entry(1, 1_700_000_000_123_456_000));

    assert_eq!(shown.id, decision_id(1).to_string());
    assert_eq!(shown.occurred_at, "2023-11-14T22:13:20.123456Z");
    assert_eq!(shown.decision, "deny");
    assert_eq!(shown.reason, "permission_missing");
    assert_eq!(shown.subject_kind.as_deref(), Some("user"));
    assert_eq!(shown.denied, ["user:read"]);
    assert_eq!(shown.policy_version, Some(7));
    let text = serde_json::to_string(&shown).unwrap();
    assert!(!text.contains("deadbeef"));
    assert!(text.contains("\"latencyUs\":1200"));
}

#[test]
fn the_route_and_the_project_of_a_decision_are_shown_when_it_has_them() {
    let mut found = entry(2, 1_700_000_000_000_000_000);
    found.record.route_id = Some(decision_id(5));
    found.record.project_id = Some(decision_id(6));

    let shown = AccessDecisionResponse::from(&found);

    assert_eq!(shown.route_id, Some(decision_id(5).to_string()));
    assert_eq!(shown.project_id, Some(decision_id(6).to_string()));
}

#[test]
fn a_page_carries_the_encoded_cursor_of_the_next_page() {
    let cursor = AccessLogCursor {
        timestamp_nanos: 5,
        returned: 2,
    };
    let page = AccessDecisionPage {
        entries: vec![entry(1, 5)],
        next: Some(cursor),
    };

    let shown = AccessDecisionPageResponse::from(&page);

    assert_eq!(shown.items.len(), 1);
    assert_eq!(shown.next_cursor, Some(cursor.encode()));
}

#[test]
fn the_last_page_has_no_cursor() {
    let page = AccessDecisionPage {
        entries: Vec::new(),
        next: None,
    };

    assert_eq!(AccessDecisionPageResponse::from(&page).next_cursor, None);
}

#[test]
fn a_range_alone_makes_a_query_with_the_default_page_size() {
    let query = window().into_query(actor()).unwrap();

    assert_eq!(query.limit, 30);
    assert_eq!(query.cursor, None);
    assert_eq!(query.actor, actor());
    assert_eq!(query.filter, iam_domain::AccessLogFilter::default());
    assert_eq!(
        query.until.duration_since(query.from).unwrap(),
        Duration::from_hours(1)
    );
}

#[test]
fn every_filter_is_carried_into_the_query() {
    let route = "0190f2a8-7b3c-7d4e-8f10-0000000000aa";
    let params = ListAccessDecisionsParams {
        limit: Some(200),
        after: Some("1a.2".to_owned()),
        subject_id: Some("user-1".to_owned()),
        subject_kind: Some("service".to_owned()),
        decision: Some("deny".to_owned()),
        reason: Some("permission_missing".to_owned()),
        upstream: Some("user-service".to_owned()),
        route_id: Some(route.to_owned()),
        status: Some(403),
        ..window()
    };

    let query = params.into_query(actor()).unwrap();

    assert_eq!(query.limit, 200);
    assert_eq!(
        query.cursor,
        Some(AccessLogCursor {
            timestamp_nanos: 0x1a,
            returned: 2,
        })
    );
    assert_eq!(query.filter.subject_id.as_deref(), Some("user-1"));
    assert_eq!(query.filter.subject_kind, Some(SubjectKind::Service));
    assert_eq!(query.filter.decision, Some(AccessDecision::Deny));
    assert_eq!(query.filter.reason, Some(DecisionReason::PermissionMissing));
    assert_eq!(query.filter.upstream.as_deref(), Some("user-service"));
    assert_eq!(query.filter.route_id, Some(Uuid::parse(route).unwrap()));
    assert_eq!(query.filter.status, Some(403));
}

#[rstest]
#[case::no_from(ListAccessDecisionsParams { from: None, ..window() }, "from")]
#[case::no_until(ListAccessDecisionsParams { until: None, ..window() }, "until")]
#[case::bad_from(ListAccessDecisionsParams { from: Some("yesterday".to_owned()), ..window() }, "from")]
#[case::bad_until(ListAccessDecisionsParams { until: Some("1969-12-31T23:59:59Z".to_owned()), ..window() }, "until")]
#[case::bad_cursor(ListAccessDecisionsParams { after: Some("zz".to_owned()), ..window() }, "after")]
#[case::bad_kind(ListAccessDecisionsParams { subject_kind: Some("robot".to_owned()), ..window() }, "subjectKind")]
#[case::bad_decision(ListAccessDecisionsParams { decision: Some("maybe".to_owned()), ..window() }, "decision")]
#[case::bad_reason(ListAccessDecisionsParams { reason: Some("because".to_owned()), ..window() }, "reason")]
#[case::empty_upstream(ListAccessDecisionsParams { upstream: Some(String::new()), ..window() }, "upstream")]
#[case::empty_subject(ListAccessDecisionsParams { subject_id: Some(String::new()), ..window() }, "subjectId")]
#[case::bad_route(ListAccessDecisionsParams { route_id: Some("nope".to_owned()), ..window() }, "routeId")]
fn a_parameter_that_is_not_valid_is_a_violation_of_its_property(
    #[case] params: ListAccessDecisionsParams,
    #[case] property: &str,
) {
    let error = params.into_query(actor()).unwrap_err();

    assert_eq!(property_of(error), property);
}

#[test]
fn the_range_is_a_pair_of_instants_after_1970() {
    let query = window().into_query(actor()).unwrap();

    assert!(query.from > SystemTime::UNIX_EPOCH);
}
