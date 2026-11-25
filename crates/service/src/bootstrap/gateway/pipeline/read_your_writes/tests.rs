use axum::body::Body;
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::Response;
use iam_domain::PolicyVersion;
use rstest::rstest;

use super::{carry_version, requested_version};

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        headers.append(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    headers
}

fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

#[test]
fn a_request_without_header_or_cookie_names_no_version() {
    assert_eq!(requested_version(&HeaderMap::new()), None);
    assert_eq!(requested_version(&headers(&[("cookie", "a=1; b=2")])), None);
}

#[test]
fn the_header_names_the_version() {
    assert_eq!(
        requested_version(&headers(&[("x-iam-min-policy-version", "42")])),
        Some(version(42))
    );
}

#[test]
fn the_cookie_names_the_version_among_other_cookies_and_headers() {
    let headers = headers(&[
        ("cookie", "theme=dark"),
        ("cookie", "__Host-auth_token=t; __Host-iam_pv=7; other=1"),
    ]);

    assert_eq!(requested_version(&headers), Some(version(7)));
}

#[test]
fn the_header_wins_over_the_cookie() {
    let headers = headers(&[
        ("x-iam-min-policy-version", "9"),
        ("cookie", "__Host-iam_pv=3"),
    ]);

    assert_eq!(requested_version(&headers), Some(version(9)));
}

#[rstest]
#[case("")]
#[case("-1")]
#[case("+1")]
#[case("1.5")]
#[case("abc")]
#[case("99999999999999999999")]
fn a_value_that_is_no_version_names_nothing(#[case] raw: &str) {
    assert_eq!(
        requested_version(&headers(&[("x-iam-min-policy-version", raw)])),
        None
    );
    let cookie = format!("__Host-iam_pv={raw}");
    let mut with_cookie = HeaderMap::new();
    with_cookie.insert(COOKIE, HeaderValue::from_str(&cookie).unwrap());
    assert_eq!(requested_version(&with_cookie), None);
}

#[test]
fn an_unreadable_header_falls_back_to_the_cookie() {
    let headers = headers(&[
        ("x-iam-min-policy-version", "abc"),
        ("cookie", "__Host-iam_pv=3"),
    ]);

    assert_eq!(requested_version(&headers), Some(version(3)));
}

fn response(version: Option<&str>) -> Response {
    let mut builder = Response::builder();
    if let Some(version) = version {
        builder = builder.header("iam-policy-version", version);
    }
    builder.body(Body::empty()).unwrap()
}

#[test]
fn a_response_with_a_policy_version_sets_the_cookie_with_its_attributes() {
    let mut response = response(Some("12"));

    carry_version(&mut response);

    let cookie = response
        .headers()
        .get(SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(
        cookie,
        "__Host-iam_pv=12; Max-Age=60; Path=/; Secure; HttpOnly; SameSite=Strict"
    );
}

#[test]
fn the_cookie_is_added_beside_the_cookies_of_the_upstream() {
    let mut response = response(Some("12"));
    response
        .headers_mut()
        .append(SET_COOKIE, HeaderValue::from_static("session=1"));

    carry_version(&mut response);

    assert_eq!(response.headers().get_all(SET_COOKIE).iter().count(), 2);
}

#[rstest]
#[case(None)]
#[case(Some("-3"))]
#[case(Some("soon"))]
fn a_response_without_a_valid_policy_version_sets_no_cookie(#[case] raw: Option<&str>) {
    let mut response = response(raw);

    carry_version(&mut response);

    assert!(response.headers().get(SET_COOKIE).is_none());
}
