use iam_domain::SessionId;
use validator::Validate as _;

use super::RevokeSessionsRequest;
use crate::error::IamError;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";

fn request(user: &str, sessions: &[&str]) -> RevokeSessionsRequest {
    RevokeSessionsRequest {
        user_id: user.to_owned(),
        session_ids: sessions.iter().map(|value| (*value).to_owned()).collect(),
    }
}

fn paths(error: IamError) -> Vec<String> {
    let IamError::Invalid(violations) = error else {
        panic!("an invalid request");
    };
    violations
        .into_iter()
        .map(|violation| violation.property_path)
        .collect()
}

#[test]
fn a_user_with_sessions_is_parsed_in_order() {
    let parsed = request(USER, &["sid-b", "sid-a"]).parse().unwrap();

    let sessions: Vec<_> = parsed.session_ids.iter().map(SessionId::as_str).collect();
    assert_eq!(sessions, ["sid-b", "sid-a"]);
}

#[test]
fn an_empty_list_is_the_cutoff_of_the_user() {
    assert_eq!(request(USER, &[]).parse().unwrap().session_ids.len(), 0);
}

#[test]
fn a_user_that_is_not_a_uuid_is_refused_by_its_property() {
    let error = request("not-a-uuid", &[]).parse().unwrap_err();

    assert_eq!(paths(error), ["userId"]);
}

#[test]
fn a_session_id_that_is_blank_or_not_visible_ascii_is_refused_by_its_index() {
    let error = request(USER, &["sid-1", "", "bad id"]).parse().unwrap_err();

    assert_eq!(paths(error), ["sessionIds[1]", "sessionIds[2]"]);
}

#[test]
fn more_than_the_limit_of_sessions_is_refused() {
    let many: Vec<String> = (0..=100).map(|index| format!("sid-{index}")).collect();
    let refs: Vec<&str> = many.iter().map(String::as_str).collect();

    assert!(request(USER, &refs).validate().is_err());
    assert!(request(USER, &refs[..100]).validate().is_ok());
}

#[test]
fn the_canonical_form_differs_by_user_and_by_sessions() {
    let base = request(USER, &["sid-1"]).canonical_form();

    assert_ne!(base, request(USER, &["sid-2"]).canonical_form());
    assert_ne!(
        base,
        request("0190f2a8-7b3c-7d4e-8f10-1234567890ac", &["sid-1"]).canonical_form()
    );
    assert_eq!(
        base,
        request(&USER.to_uppercase(), &["sid-1"]).canonical_form()
    );
}
