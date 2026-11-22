use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessToken, AccessTokenParts, ServiceName, SessionId, SubjectId, TokenId, TokenIdentity,
    TokenRejection,
};
use rstest::rstest;
use serde_json::json;
use shared_domain::Uuid;
use validator::Validate as _;

use super::{TokenResolutionRequest, TokenResolutionResponse};
use crate::principal::Principal;
use crate::query::resolve_subject_token::TokenResolution;

fn principal(subject: SubjectId, session: Option<&str>, expires_in: Duration) -> Principal {
    Principal::from(TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject,
        session: session.map(|sid| SessionId::new(sid).unwrap()),
        token_id: TokenId::new("jti-9").unwrap(),
        roles: vec!["ROLE_USER".to_owned(), "ROLE_ADMIN".to_owned()],
        issued_at: SystemTime::UNIX_EPOCH,
        expires_at: SystemTime::UNIX_EPOCH.checked_add(expires_in).unwrap(),
    })))
}

fn user() -> SubjectId {
    SubjectId::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap())
}

fn request(credential: &str) -> TokenResolutionRequest {
    TokenResolutionRequest {
        credential: credential.to_owned(),
    }
}

#[test]
fn a_resolved_user_token_is_answered_with_every_claim() {
    let user = principal(user(), Some("session-1"), Duration::from_hours(500_000));

    let response = TokenResolutionResponse::from(TokenResolution::Resolved(user));

    assert_eq!(
        serde_json::to_value(response).unwrap(),
        json!({
            "resolved": true,
            "subjectId": "0190f2a8-7b3c-7d4e-8f10-1234567890ab",
            "subjectKind": "user",
            "sessionId": "session-1",
            "roles": ["ROLE_USER", "ROLE_ADMIN"],
            "expiresAt": 1_800_000_000_i64,
        })
    );
}

#[test]
fn a_resolved_service_token_has_its_service_name_and_no_session() {
    let name = ServiceName::new("billing").unwrap();
    let service = principal(SubjectId::Service(name), None, Duration::from_secs(60));

    let response = TokenResolutionResponse::resolved(&service);

    assert_eq!(
        serde_json::to_value(response).unwrap(),
        json!({
            "resolved": true,
            "subjectId": "billing",
            "subjectKind": "service",
            "roles": ["ROLE_USER", "ROLE_ADMIN"],
            "expiresAt": 60,
        })
    );
}

#[rstest]
#[case::missing(TokenRejection::Missing, "token_missing")]
#[case::invalid(TokenRejection::Invalid, "token_invalid")]
#[case::expired(TokenRejection::Expired, "token_expired")]
#[case::revoked(TokenRejection::Revoked, "token_revoked")]
fn a_refused_credential_is_answered_with_its_reason_code_only(
    #[case] rejection: TokenRejection,
    #[case] code: &str,
) {
    let response = TokenResolutionResponse::from(TokenResolution::Unresolved(rejection));

    assert_eq!(
        serde_json::to_value(response).unwrap(),
        json!({ "resolved": false, "reason": code })
    );
}

fn principal_expiring_at(time: SystemTime) -> Principal {
    Principal::from(TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject: user(),
        session: Some(SessionId::new("s").unwrap()),
        token_id: TokenId::new("jti-9").unwrap(),
        roles: Vec::new(),
        issued_at: SystemTime::UNIX_EPOCH,
        expires_at: time,
    })))
}

#[test]
fn an_expiry_before_1970_is_zero() {
    let before = SystemTime::UNIX_EPOCH
        .checked_sub(Duration::from_secs(10))
        .unwrap();

    let response = TokenResolutionResponse::resolved(&principal_expiring_at(before));

    assert_eq!(response.expires_at, Some(0));
}

#[test]
fn the_request_reads_its_credential_and_refuses_unknown_members() {
    let parsed: TokenResolutionRequest =
        serde_json::from_value(json!({ "credential": "abc" })).unwrap();

    assert_eq!(parsed.credential, "abc");
    assert!(
        serde_json::from_value::<TokenResolutionRequest>(json!({ "credential": "a", "x": 1 }))
            .is_err()
    );
    assert!(serde_json::from_value::<TokenResolutionRequest>(json!({})).is_err());
}

#[rstest]
#[case::empty("", true)]
#[case::at_the_limit(&"a".repeat(8192), true)]
#[case::above_the_limit(&"a".repeat(8193), false)]
fn the_credential_may_be_empty_but_not_longer_than_the_limit(
    #[case] credential: &str,
    #[case] valid: bool,
) {
    assert_eq!(request(credential).validate().is_ok(), valid);
}

#[test]
fn the_printed_request_never_shows_the_credential() {
    let printed = format!("{:?}", request("raw-secret-token"));

    assert!(printed.starts_with("TokenResolutionRequest"), "{printed}");
    assert!(!printed.contains("raw-secret-token"), "{printed}");
}
