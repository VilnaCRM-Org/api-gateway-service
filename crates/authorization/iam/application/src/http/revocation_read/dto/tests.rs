use iam_domain::RevocationSource;
use rstest::rstest;
use serde_json::json;
use validator::Validate as _;

use super::{
    GlobalTokenCutoffResponse, ListSessionRevocationsParams, SessionRevocationPageResponse,
    SessionRevocationResponse, UserTokenCutoffResponse, parse_user,
};
use crate::error::IamError;
use crate::query::get_user_token_cutoff::UserTokenCutoffView;
use crate::query::list_session_revocations::SessionRevocationPage;
use crate::revocation_read_fixtures::{
    global_cutoff, operator, revocation, user_cutoff, user_cutoff_view,
};

fn params(value: serde_json::Value) -> ListSessionRevocationsParams {
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
fn an_operator_revocation_is_shown_with_its_source_actor_session_user_and_time() {
    let response = SessionRevocationResponse::from(&revocation(1));

    assert_eq!(response.id, "00000000-0000-0000-0000-000000000001");
    assert_eq!(response.session_id, "session-1");
    assert_eq!(response.user_id, "0190f2a8-7b3c-7d4e-8f10-1234567890ab");
    assert_eq!(response.source, "operator");
    assert_eq!(response.actor, operator().to_string());
    assert!(response.revoked_at.ends_with('Z'));
}

#[test]
fn a_user_service_revocation_names_the_user_service_actor() {
    let response = SessionRevocationResponse::from(&revocation(2));

    assert_eq!(response.source, "user-service");
    assert_eq!(response.actor, "system:user-service");
}

#[test]
fn a_page_lists_its_items_and_names_the_next_cursor_only_when_one_follows() {
    let page = SessionRevocationPage {
        revocations: vec![revocation(2), revocation(1)],
        next_after: Some(revocation(1).id),
    };
    let last = SessionRevocationPage {
        revocations: vec![revocation(1)],
        next_after: None,
    };

    let body = serde_json::to_value(SessionRevocationPageResponse::from(&page)).unwrap();
    let last_body = serde_json::to_value(SessionRevocationPageResponse::from(&last)).unwrap();

    assert_eq!(body["items"].as_array().unwrap().len(), 2);
    assert_eq!(body["nextCursor"], "00000000-0000-0000-0000-000000000001");
    assert!(last_body.get("nextCursor").is_none());
}

#[test]
fn a_user_cutoff_is_shown_with_its_instant_source_and_actor() {
    let body = serde_json::to_value(UserTokenCutoffResponse::from(&user_cutoff_view())).unwrap();

    assert_eq!(body["userId"], "0190f2a8-7b3c-7d4e-8f10-1234567890ab");
    assert_eq!(body["source"], "operator");
    assert_eq!(body["actor"], operator().to_string());
    assert!(body["tokensValidAfter"].as_str().unwrap().ends_with('Z'));
    assert!(body["updatedAt"].as_str().unwrap().ends_with('Z'));
}

#[test]
fn a_user_cutoff_without_a_known_actor_omits_it() {
    let view = UserTokenCutoffView {
        cutoff: user_cutoff(RevocationSource::Operator),
        actor: None,
    };

    let body = serde_json::to_value(UserTokenCutoffResponse::from(&view)).unwrap();

    assert!(body.get("actor").is_none());
}

#[test]
fn the_global_cutoff_is_shown_as_an_operator_cutoff_with_its_actor() {
    let body = serde_json::to_value(GlobalTokenCutoffResponse::from(&global_cutoff())).unwrap();

    assert_eq!(body["source"], "operator");
    assert_eq!(body["actor"], operator().to_string());
    assert!(body["tokensValidAfter"].as_str().unwrap().ends_with('Z'));
    assert!(body["setAt"].as_str().unwrap().ends_with('Z'));
}

#[test]
fn absent_parameters_ask_for_the_first_page_of_thirty_without_filters() {
    let query = params(json!({})).into_query().unwrap();

    assert_eq!(query.limit, 30);
    assert_eq!(query.after, None);
    assert_eq!(query.user, None);
    assert_eq!(query.source, None);
    assert_eq!((query.from, query.until), (None, None));
}

#[test]
fn every_parameter_reaches_the_query() {
    let query = params(json!({
        "limit": 5,
        "after": "00000000-0000-0000-0000-000000000001",
        "userId": "0190f2a8-7b3c-7d4e-8f10-1234567890ab",
        "source": "user-service",
        "from": "2026-11-23T08:00:00Z",
        "until": "2026-11-23T09:00:00Z",
    }))
    .into_query()
    .unwrap();

    assert_eq!(query.limit, 5);
    assert_eq!(query.after, Some(revocation(1).id));
    assert_eq!(query.user, Some(revocation(1).user));
    assert_eq!(query.source, Some(RevocationSource::UserService));
    assert!(query.from < query.until);
}

#[rstest]
#[case(json!({"after": "nope"}), "after", "uuid")]
#[case(json!({"userId": "nope"}), "userId", "uuid")]
#[case(json!({"source": "other"}), "source", "choice")]
#[case(json!({"from": "yesterday"}), "from", "format")]
#[case(json!({"until": "1960-01-01T00:00:00Z"}), "until", "format")]
fn an_invalid_parameter_is_a_violation_of_that_parameter(
    #[case] value: serde_json::Value,
    #[case] property: &str,
    #[case] code: &str,
) {
    let error = params(value).into_query().unwrap_err();

    assert_eq!(violation_of(error), (property.to_owned(), code.to_owned()));
}

#[rstest]
#[case(0)]
#[case(101)]
#[case(-1)]
fn a_limit_outside_one_to_a_hundred_fails_validation(#[case] limit: i32) {
    assert!(params(json!({"limit": limit})).validate().is_err());
}

#[test]
fn an_unknown_parameter_is_refused() {
    assert!(serde_json::from_value::<ListSessionRevocationsParams>(json!({"x": 1})).is_err());
}

#[test]
fn a_user_that_is_not_a_uuid_is_a_violation_of_the_named_property() {
    let error = parse_user("userId", "nope").unwrap_err();

    assert_eq!(
        violation_of(error),
        ("userId".to_owned(), "uuid".to_owned())
    );
}
