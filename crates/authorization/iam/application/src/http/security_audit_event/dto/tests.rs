use iam_domain::{
    ActorRef, AuditOutcome, ChainBreak, ChainBreakCause, ChainVerification, SecurityAuditEventId,
    SecurityAuditFilter,
};
use rstest::rstest;
use serde_json::json;
use validator::Validate as _;

use super::{
    AnchorValue, ChainVerificationResponse, ListSecurityAuditEventsParams,
    SecurityAuditEventPageResponse, SecurityAuditEventResponse, VerifyChainParams, parse_anchors,
};
use crate::error::IamError;
use crate::query::get_security_audit_events::SecurityAuditEventPage;
use crate::security_audit_fixtures::{actor, record, uuid};

fn params(value: serde_json::Value) -> ListSecurityAuditEventsParams {
    serde_json::from_value(value).unwrap()
}

fn violation_of(error: IamError) -> (String, String) {
    let IamError::Invalid(violations) = error else {
        panic!("not a validation failure: {error:?}");
    };
    (
        violations[0].property_path.clone(),
        violations[0].code.clone(),
    )
}

#[test]
fn a_committed_record_is_shown_with_its_summaries_and_its_place_in_the_chain() {
    let response = SecurityAuditEventResponse::from(&record(1, AuditOutcome::Committed));

    assert_eq!(response.id, "00000000-0000-0000-0000-000000000001");
    assert_eq!(response.seq, 1);
    assert_eq!(response.actor, actor().to_string());
    assert_eq!(response.action, "role.update");
    assert_eq!(response.target_type, "role");
    assert_eq!(response.target_id, "r-1");
    assert_eq!(response.before.as_deref(), Some("name=readers"));
    assert_eq!(response.after.as_deref(), Some("name=writers"));
    assert_eq!(response.outcome, "committed");
    assert_eq!(response.policy_version, Some(7));
    assert_eq!(response.reason, None);
    assert_eq!(response.prev_hash, "0".repeat(64));
    assert_eq!(response.hash, format!("{}01", "0".repeat(62)));
    assert!(response.occurred_at.ends_with('Z'));
}

#[test]
fn a_rejected_record_is_shown_with_its_reason_and_without_the_absent_members() {
    let response = SecurityAuditEventResponse::from(&record(2, AuditOutcome::Rejected));
    let body = serde_json::to_value(&response).unwrap();

    assert_eq!(body["outcome"], "rejected");
    assert_eq!(body["reason"], "forbidden");
    for absent in [
        "callerService",
        "scope",
        "before",
        "after",
        "policyVersion",
        "requestId",
    ] {
        assert!(body.get(absent).is_none(), "{absent}");
    }
}

#[test]
fn a_page_lists_its_records_and_the_cursor_of_the_older_page() {
    let page = SecurityAuditEventPage {
        events: vec![
            record(2, AuditOutcome::Rejected),
            record(1, AuditOutcome::Committed),
        ],
        next_before: Some(1),
    };
    let last = SecurityAuditEventPage {
        next_before: None,
        ..page.clone()
    };

    let body = serde_json::to_value(SecurityAuditEventPageResponse::from(&page)).unwrap();
    let final_body = serde_json::to_value(SecurityAuditEventPageResponse::from(&last)).unwrap();

    assert_eq!(body["items"].as_array().unwrap().len(), 2);
    assert_eq!(body["items"][0]["seq"], 2);
    assert_eq!(body["nextCursor"], "1");
    assert!(final_body.get("nextCursor").is_none());
}

#[test]
fn without_parameters_the_first_page_of_30_has_no_condition() {
    let query = params(json!({})).into_query(actor()).unwrap();

    assert_eq!(query.limit, 30);
    assert_eq!(query.before_seq, None);
    assert_eq!(query.filter, SecurityAuditFilter::new());
    assert_eq!(query.actor, actor());
}

#[test]
fn every_parameter_becomes_a_condition_of_the_query() {
    let query = params(json!({
        "limit": 5,
        "after": "9",
        "from": "2026-11-23T08:00:00Z",
        "until": "2026-11-24T08:00:00Z",
        "actor": "service:core",
        "action": "role.update",
        "targetType": "role",
        "targetId": "r-1",
        "outcome": "rejected",
    }))
    .into_query(actor())
    .unwrap();

    assert_eq!(query.limit, 5);
    assert_eq!(query.before_seq, Some(9));
    assert_eq!(query.filter.since_micros(), Some(1_795_420_800_000_000));
    assert_eq!(query.filter.until_micros(), Some(1_795_507_200_000_000));
    assert_eq!(
        query.filter.actor(),
        Some(&ActorRef::parse("service:core").unwrap())
    );
    assert_eq!(
        query.filter.action().map(iam_domain::AuditAction::as_str),
        Some("role.update")
    );
    assert_eq!(query.filter.target_type(), Some("role"));
    assert_eq!(query.filter.target_id(), Some("r-1"));
    assert_eq!(query.filter.outcome(), Some(AuditOutcome::Rejected));
}

#[rstest]
#[case::zero(json!({ "limit": 0 }))]
#[case::negative(json!({ "limit": -1 }))]
#[case::too_large(json!({ "limit": 101 }))]
fn a_limit_outside_1_to_100_fails_validation(#[case] value: serde_json::Value) {
    assert!(params(value).validate().is_err());
}

#[rstest]
#[case::cursor_text(json!({ "after": "nope" }), "after", "format")]
#[case::cursor_zero(json!({ "after": "0" }), "after", "format")]
#[case::cursor_negative(json!({ "after": "-3" }), "after", "format")]
#[case::from_text(json!({ "from": "yesterday" }), "from", "format")]
#[case::until_before_1970(json!({ "until": "1969-12-31T23:59:59Z" }), "until", "format")]
#[case::actor(json!({ "actor": "someone" }), "actor", "format")]
#[case::action(json!({ "action": "Role" }), "action", "format")]
#[case::outcome(json!({ "outcome": "maybe" }), "outcome", "choice")]
#[case::target_type(json!({ "targetType": "Role" }), "targetType", "format")]
#[case::target_id(json!({ "targetType": "role", "targetId": "" }), "targetId", "format")]
#[case::target_id_alone(json!({ "targetId": "r-1" }), "targetType", "required")]
fn a_parameter_that_is_not_valid_is_a_violation_of_that_parameter(
    #[case] value: serde_json::Value,
    #[case] property: &str,
    #[case] code: &str,
) {
    let error = params(value).into_query(actor()).unwrap_err();

    assert_eq!(violation_of(error), (property.to_owned(), code.to_owned()));
}

#[test]
fn an_unknown_parameter_is_refused() {
    let refused = serde_json::from_value::<ListSecurityAuditEventsParams>(json!({ "sort": "asc" }));

    assert!(refused.is_err());
}

const HASH: &str = "00000000000000000000000000000000000000000000000000000000000000ab";

fn anchor(seq: i64, hash: &str) -> AnchorValue {
    AnchorValue {
        seq,
        hash: hash.to_owned(),
    }
}

#[test]
fn a_valid_verification_shows_its_status_and_count_only() {
    let response = ChainVerificationResponse::from(&ChainVerification::valid(5));

    assert_eq!(
        serde_json::to_value(&response).unwrap(),
        json!({ "status": "valid", "recordsChecked": 5 })
    );
}

#[rstest]
#[case::a_digest(ChainBreakCause::Digest, "digest")]
#[case::an_anchor(ChainBreakCause::Anchor, "anchor")]
fn an_invalid_verification_shows_the_record_the_place_and_the_cause(
    #[case] cause: ChainBreakCause,
    #[case] name: &str,
) {
    let id = SecurityAuditEventId::from_uuid(uuid(3));
    let verification = ChainVerification::invalid(3, ChainBreak::new(3, Some(id), cause));

    let response = ChainVerificationResponse::from(&verification);

    assert_eq!(
        serde_json::to_value(&response).unwrap(),
        json!({
            "status": "invalid",
            "recordsChecked": 3,
            "invalidRecordId": "00000000-0000-0000-0000-000000000003",
            "invalidSeq": 3,
            "cause": name,
        })
    );
}

#[test]
fn a_missing_record_has_no_id_in_the_response() {
    let broken = ChainBreak::new(9, None, ChainBreakCause::AnchorMissing);

    let response = ChainVerificationResponse::from(&ChainVerification::invalid(2, broken));

    assert_eq!(response.invalid_record_id, None);
    assert_eq!(response.invalid_seq, Some(9));
    assert_eq!(response.cause.as_deref(), Some("anchor_missing"));
}

#[test]
fn anchors_are_parsed_from_comma_separated_pairs() {
    let anchors = VerifyChainParams {
        anchors: Some(format!("2:{HASH},7:{}", "f".repeat(64))),
    }
    .into_anchors()
    .unwrap();

    assert_eq!(anchors.len(), 2);
    assert_eq!(anchors[0].seq(), 2);
    assert_eq!(anchors[0].hash().to_string(), HASH);
    assert_eq!(anchors[1].seq(), 7);
    assert_eq!(anchors[1].hash().to_string(), "f".repeat(64));
}

#[rstest]
#[case::absent(None)]
#[case::empty(Some(""))]
fn no_anchors_is_an_empty_list(#[case] anchors: Option<&str>) {
    let parsed = VerifyChainParams {
        anchors: anchors.map(str::to_owned),
    }
    .into_anchors()
    .unwrap();

    assert_eq!(parsed, Vec::new());
}

#[rstest]
#[case::no_separator("nope".to_owned())]
#[case::no_hash("2:".to_owned())]
#[case::no_seq(":ab".to_owned())]
#[case::a_seq_that_is_not_a_number(format!("x:{HASH}"))]
#[case::a_short_hash("2:abcd".to_owned())]
#[case::an_upper_case_hash(format!("2:{}", "A".repeat(64)))]
#[case::a_hash_that_is_not_hex(format!("2:{}", "g".repeat(64)))]
#[case::an_odd_length_hash(format!("2:{}", "a".repeat(63)))]
#[case::a_multi_byte_hash(format!("2:{}", "\u{e9}".repeat(32)))]
fn a_malformed_anchor_is_a_format_violation_of_anchors(#[case] anchors: String) {
    let error = VerifyChainParams {
        anchors: Some(anchors),
    }
    .into_anchors()
    .unwrap_err();

    assert_eq!(
        violation_of(error),
        ("anchors".to_owned(), "format".to_owned())
    );
}

#[test]
fn an_anchor_below_the_first_sequence_number_is_a_range_violation() {
    let error = parse_anchors(&[anchor(0, HASH)]).unwrap_err();

    assert_eq!(
        violation_of(error),
        ("anchors".to_owned(), "range".to_owned())
    );
}

#[test]
fn more_than_a_hundred_anchors_are_a_count_violation_and_a_hundred_are_accepted() {
    let hundred: Vec<_> = (1..=100).map(|seq| anchor(seq, HASH)).collect();
    let mut too_many = hundred.clone();
    too_many.push(anchor(101, HASH));

    assert_eq!(parse_anchors(&hundred).unwrap().len(), 100);
    assert_eq!(
        violation_of(parse_anchors(&too_many).unwrap_err()),
        ("anchors".to_owned(), "count".to_owned())
    );
}
