use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, COOKIE};
use axum::http::request::Parts;
use axum::http::{HeaderValue, Request};
use axum::response::Response;
use iam_application::Principal;
use iam_domain::{
    AccessToken, AccessTokenParts, ServiceName, SessionId, SubjectId, TokenId, TokenIdentity,
};
use rstest::rstest;
use shared_domain::Uuid;

use super::{Propagated, rewrite, rewrite_anonymous, stamp_version};
use crate::bootstrap::gateway::pipeline::ClientAddress;

const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";

fn principal(subject: SubjectId, session: Option<&str>) -> Principal {
    Principal::from(TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject,
        session: session.map(|sid| SessionId::new(sid).unwrap()),
        token_id: TokenId::new("jti-1").unwrap(),
        roles: vec!["ROLE_USER".to_owned()],
        issued_at: SystemTime::UNIX_EPOCH,
        expires_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_mins(15))
            .unwrap(),
    })))
}

fn user() -> Principal {
    principal(
        SubjectId::User(Uuid::parse(USER).unwrap()),
        Some("session-1"),
    )
}

fn parts(headers: &[(&str, &str)], client: Option<IpAddr>) -> Parts {
    let mut builder = Request::get("/api/users/1");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let mut request = builder.body(Body::empty()).unwrap();
    if let Some(ip) = client {
        request
            .extensions_mut()
            .insert(ClientAddress::from(SocketAddr::new(ip, 4000)));
    }
    request.into_parts().0
}

fn rewritten(parts: &mut Parts, principal: &Principal, forward_credentials: bool) {
    rewrite(
        parts,
        &Propagated {
            principal,
            version: 7,
            forward_credentials,
        },
    );
}

fn text<'parts>(parts: &'parts Parts, name: &str) -> Option<&'parts str> {
    parts
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
}

#[test]
fn the_principal_headers_carry_what_the_decision_was_made_on() {
    let mut parts = parts(&[], Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))));

    rewritten(&mut parts, &user(), false);

    assert_eq!(text(&parts, "x-iam-subject"), Some(USER));
    assert_eq!(text(&parts, "x-iam-subject-kind"), Some("user"));
    assert_eq!(text(&parts, "x-iam-session"), Some("session-1"));
    assert_eq!(text(&parts, "x-iam-policy-version"), Some("7"));
    assert_eq!(text(&parts, "x-forwarded-for"), Some("203.0.113.9"));
}

#[test]
fn a_service_principal_has_its_name_as_subject_and_no_session_header() {
    let service = principal(
        SubjectId::Service(ServiceName::new("billing").unwrap()),
        None,
    );
    let mut parts = parts(&[("x-iam-session", "forged")], None);

    rewritten(&mut parts, &service, false);

    assert_eq!(text(&parts, "x-iam-subject"), Some("billing"));
    assert_eq!(text(&parts, "x-iam-subject-kind"), Some("service"));
    assert_eq!(parts.headers.get("x-iam-session"), None);
}

#[test]
fn forged_claims_never_survive_and_the_gateway_values_replace_them() {
    let mut parts = parts(
        &[
            ("x-iam-subject", "forged"),
            ("x-iam-policy-version", "999"),
            ("x-iam-anything", "forged"),
            ("forwarded", "for=6.6.6.6"),
            ("x-forwarded-for", "6.6.6.6"),
            ("x-forwarded-host", "evil.test"),
            ("x-request-id", "request-1"),
            ("x-other", "kept"),
        ],
        Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
    );

    rewritten(&mut parts, &user(), false);

    assert_eq!(text(&parts, "x-iam-subject"), Some(USER));
    assert_eq!(text(&parts, "x-iam-policy-version"), Some("7"));
    assert_eq!(parts.headers.get("x-iam-anything"), None);
    assert_eq!(parts.headers.get("forwarded"), None);
    assert_eq!(parts.headers.get("x-forwarded-host"), None);
    assert_eq!(parts.headers.get_all("x-forwarded-for").iter().count(), 1);
    assert_eq!(text(&parts, "x-forwarded-for"), Some("203.0.113.9"));
    assert_eq!(text(&parts, "x-request-id"), Some("request-1"));
    assert_eq!(text(&parts, "x-other"), Some("kept"));
}

#[test]
fn a_forged_forwarded_for_is_dropped_when_the_client_address_is_unknown() {
    let mut parts = parts(&[("x-forwarded-for", "6.6.6.6")], None);

    rewritten(&mut parts, &user(), false);

    assert_eq!(parts.headers.get("x-forwarded-for"), None);
}

#[test]
fn credentials_go_byte_for_byte_to_an_upstream_that_takes_them() {
    let cookie = "theme=dark;__Host-auth_token=abc.def ;  other=1";
    let mut parts = parts(
        &[("authorization", "Bearer abc.def"), ("cookie", cookie)],
        None,
    );

    rewritten(&mut parts, &user(), true);

    assert_eq!(text(&parts, "authorization"), Some("Bearer abc.def"));
    assert_eq!(text(&parts, "cookie"), Some(cookie));
}

#[test]
fn credentials_are_removed_for_any_other_upstream_and_the_other_cookies_stay() {
    let mut parts = parts(
        &[
            ("authorization", "Bearer abc.def"),
            ("cookie", "theme=dark; __Host-auth_token=abc.def; other=1"),
            ("cookie", "__Host-auth_token=second"),
            ("cookie", "lang=uk"),
        ],
        None,
    );

    rewritten(&mut parts, &user(), false);

    assert_eq!(parts.headers.get(AUTHORIZATION), None);
    let cookies: Vec<&str> = parts
        .headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    assert_eq!(cookies, ["theme=dark; other=1", "lang=uk"]);
}

#[test]
fn cookies_without_the_token_are_left_byte_for_byte() {
    let mut parts = parts(&[("cookie", "a=1;b=2")], None);

    rewritten(&mut parts, &user(), false);

    assert_eq!(text(&parts, "cookie"), Some("a=1;b=2"));
}

#[test]
fn a_cookie_header_that_held_only_the_token_is_removed() {
    let mut parts = parts(&[("cookie", "__Host-auth_token=abc")], None);

    rewritten(&mut parts, &user(), false);

    assert_eq!(parts.headers.get(COOKIE), None);
}

#[test]
fn a_cookie_that_only_resembles_the_token_cookie_stays() {
    let mut parts = parts(
        &[("cookie", "x__Host-auth_token=1; __Host-auth_token2=2")],
        None,
    );

    rewritten(&mut parts, &user(), false);

    assert_eq!(
        text(&parts, "cookie"),
        Some("x__Host-auth_token=1; __Host-auth_token2=2")
    );
}

#[rstest]
#[case(Some(7), Some("7"))]
#[case(None, None)]
fn a_response_carries_the_policy_version_it_was_decided_on(
    #[case] version: Option<i64>,
    #[case] expected: Option<&str>,
) {
    let mut response = Response::new(Body::empty());

    stamp_version(&mut response, version);

    assert_eq!(
        response
            .headers()
            .get("x-iam-policy-version")
            .and_then(|value| value.to_str().ok()),
        expected
    );
}

#[test]
fn the_version_of_the_gateway_replaces_the_one_an_upstream_sent() {
    let mut response = Response::new(Body::empty());
    response
        .headers_mut()
        .insert("x-iam-policy-version", HeaderValue::from_static("1"));

    stamp_version(&mut response, Some(12));

    assert_eq!(
        response
            .headers()
            .get_all("x-iam-policy-version")
            .iter()
            .count(),
        1
    );
    assert_eq!(
        response.headers().get("x-iam-policy-version"),
        Some(&HeaderValue::from_static("12"))
    );
}

#[rstest]
#[case::credentials_forwarded(true)]
#[case::credentials_withheld(false)]
fn an_anonymous_request_loses_every_client_claim_and_gets_no_principal_header(
    #[case] forward_credentials: bool,
) {
    let mut parts = parts(
        &[
            ("x-iam-subject", "forged"),
            ("x-iam-policy-version", "99"),
            ("forwarded", "for=1.2.3.4"),
            ("x-forwarded-for", "1.2.3.4"),
            ("x-other", "kept"),
        ],
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))),
    );

    rewrite_anonymous(&mut parts, forward_credentials);

    assert_eq!(text(&parts, "x-iam-subject"), None);
    assert_eq!(text(&parts, "x-iam-subject-kind"), None);
    assert_eq!(text(&parts, "x-iam-session"), None);
    assert_eq!(text(&parts, "x-iam-policy-version"), None);
    assert_eq!(text(&parts, "forwarded"), None);
    assert_eq!(text(&parts, "x-forwarded-for"), Some("192.0.2.7"));
    assert_eq!(text(&parts, "x-other"), Some("kept"));
}

#[test]
fn an_anonymous_request_forwards_an_invalid_token_unchanged_only_to_a_credential_upstream() {
    let headers = [
        ("authorization", "Bearer not.a.valid.token"),
        ("cookie", "__Host-auth_token=bad; theme=dark"),
    ];
    let mut forwarded = parts(&headers, None);
    let mut withheld = parts(&headers, None);

    rewrite_anonymous(&mut forwarded, true);
    rewrite_anonymous(&mut withheld, false);

    assert_eq!(
        text(&forwarded, "authorization"),
        Some("Bearer not.a.valid.token")
    );
    assert_eq!(
        text(&forwarded, "cookie"),
        Some("__Host-auth_token=bad; theme=dark")
    );
    assert_eq!(text(&withheld, "authorization"), None);
    assert_eq!(text(&withheld, "cookie"), Some("theme=dark"));
}
