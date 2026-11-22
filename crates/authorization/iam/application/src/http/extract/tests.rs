use std::time::{Duration, SystemTime};

use axum::extract::FromRequestParts as _;
use axum::http::request::Parts;
use axum::http::{HeaderValue, Request};
use iam_domain::{
    AccessToken, AccessTokenParts, EntityVersion, IdempotencyKey, SubjectId, TokenId, TokenIdentity,
};
use rstest::rstest;
use shared_application::http::{TYPE_BLANK, TYPE_VALIDATION_FAILED, Violation};
use shared_domain::Uuid;

use super::{CallerPrincipal, IDEMPOTENCY_KEY, IdempotencyKeyHeader, IfMatchHeader};
use crate::principal::Principal;

fn parts(headers: &[(&str, HeaderValue)]) -> Parts {
    let mut builder = Request::builder();
    for (name, value) in headers {
        builder = builder.header(*name, value.clone());
    }
    builder.body(()).unwrap().into_parts().0
}

fn text(value: &str) -> HeaderValue {
    HeaderValue::from_str(value).unwrap()
}

#[test]
fn the_idempotency_key_header_is_named_like_the_specification() {
    assert_eq!(IDEMPOTENCY_KEY.as_str(), "idempotency-key");
}

#[tokio::test]
async fn a_request_without_an_idempotency_key_has_none() {
    let mut parts = parts(&[]);

    let header = IdempotencyKeyHeader::from_request_parts(&mut parts, &())
        .await
        .unwrap();

    assert_eq!(header, IdempotencyKeyHeader(None));
}

#[tokio::test]
async fn a_valid_idempotency_key_is_extracted() {
    let mut parts = parts(&[("Idempotency-Key", text("retry-7f3a"))]);

    let header = IdempotencyKeyHeader::from_request_parts(&mut parts, &())
        .await
        .unwrap();

    assert_eq!(
        header,
        IdempotencyKeyHeader(Some(IdempotencyKey::new("retry-7f3a").unwrap()))
    );
}

#[rstest]
#[case::empty(text(""))]
#[case::with_a_space(text("retry key"))]
#[case::too_long(text(&"k".repeat(256)))]
#[case::not_visible_ascii(HeaderValue::from_bytes(b"retry-\xff").unwrap())]
#[tokio::test]
async fn an_invalid_idempotency_key_is_the_422_problem_naming_the_key(#[case] value: HeaderValue) {
    let mut parts = parts(&[("idempotency-key", value)]);

    let problem = IdempotencyKeyHeader::from_request_parts(&mut parts, &())
        .await
        .unwrap_err();

    assert_eq!(problem.status, 422);
    assert_eq!(problem.r#type, TYPE_VALIDATION_FAILED);
    assert_eq!(
        problem.violations,
        vec![Violation {
            property_path: "idempotencyKey".to_owned(),
            message: "This value must contain between 1 and 255 visible ASCII characters."
                .to_owned(),
            code: "format".to_owned(),
        }]
    );
}

#[rstest]
#[case::one("\"1\"", 1)]
#[case::many("\"4096\"", 4096)]
#[case::largest("\"9223372036854775807\"", i64::MAX)]
#[tokio::test]
async fn a_strong_etag_in_if_match_is_its_entity_version(
    #[case] value: &str,
    #[case] version: i64,
) {
    let mut parts = parts(&[("If-Match", text(value))]);

    let header = IfMatchHeader::from_request_parts(&mut parts, &())
        .await
        .unwrap();

    assert_eq!(header, IfMatchHeader(EntityVersion::new(version).unwrap()));
}

#[tokio::test]
async fn an_update_without_if_match_is_the_428_problem() {
    let mut parts = parts(&[]);

    let problem = IfMatchHeader::from_request_parts(&mut parts, &())
        .await
        .unwrap_err();

    assert_eq!(problem.status, 428);
    assert_eq!(problem.title, "Precondition Required");
    assert_eq!(problem.r#type, TYPE_BLANK);
    assert_eq!(
        problem.detail.as_deref(),
        Some("The request must name the version it changes.")
    );
}

#[rstest]
#[case::unquoted(text("4"))]
#[case::weak(text("W/\"4\""))]
#[case::open_quote(text("\"4"))]
#[case::close_quote(text("4\""))]
#[case::empty_tag(text("\"\""))]
#[case::zero(text("\"0\""))]
#[case::negative(text("\"-1\""))]
#[case::plus_sign(text("\"+4\""))]
#[case::leading_zero(text("\"04\""))]
#[case::too_large(text("\"9223372036854775808\""))]
#[case::letters(text("\"abc\""))]
#[case::list(text("\"4\", \"5\""))]
#[case::any(text("*"))]
#[case::not_visible_ascii(HeaderValue::from_bytes(b"\"4\xff\"").unwrap())]
#[tokio::test]
async fn an_if_match_that_is_no_version_etag_is_the_412_problem(#[case] value: HeaderValue) {
    let mut parts = parts(&[("if-match", value)]);

    let problem = IfMatchHeader::from_request_parts(&mut parts, &())
        .await
        .unwrap_err();

    assert_eq!(problem.status, 412);
    assert_eq!(problem.title, "Precondition Failed");
    assert_eq!(problem.r#type, TYPE_BLANK);
    assert_eq!(
        problem.detail.as_deref(),
        Some("The request names a version that is not the current version.")
    );
}

fn principal() -> Principal {
    Principal::from(TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap()),
        session: None,
        token_id: TokenId::new("jti-1").unwrap(),
        roles: Vec::new(),
        issued_at: SystemTime::UNIX_EPOCH,
        expires_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_mins(15))
            .unwrap(),
    })))
}

#[tokio::test]
async fn the_principal_of_the_request_is_the_caller() {
    let mut parts = parts(&[]);
    parts.extensions.insert(principal());

    let caller = CallerPrincipal::from_request_parts(&mut parts, &())
        .await
        .unwrap();

    assert_eq!(caller, CallerPrincipal(principal()));
}

#[tokio::test]
async fn a_request_without_a_principal_is_the_401_problem() {
    let mut parts = parts(&[]);

    let problem = CallerPrincipal::from_request_parts(&mut parts, &())
        .await
        .unwrap_err();

    assert_eq!(problem.status, 401);
    assert_eq!(problem.r#type, TYPE_BLANK);
    assert_eq!(
        problem.detail.as_deref(),
        Some("A valid bearer token is required.")
    );
}
