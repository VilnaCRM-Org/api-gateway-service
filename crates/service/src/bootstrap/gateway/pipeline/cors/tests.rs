use axum::http::header::{HOST, ORIGIN, UPGRADE, VARY};
use axum::http::request::{Builder, Parts};
use axum::http::{Request, StatusCode};
use iam_domain::{CorsDraft, CorsPolicy, CorsRule, HttpMethod};

use super::*;

const CRM: &str = "https://crm.example.test";

fn policy(allow_credentials: bool) -> CorsPolicy {
    CorsPolicy::new(CorsDraft {
        origins: vec![CRM.to_owned()],
        methods: vec![HttpMethod::Get, HttpMethod::Post],
        headers: vec!["Content-Type".to_owned()],
        allow_credentials,
        max_age_seconds: 300,
    })
    .unwrap()
}

fn parts(builder: Builder) -> Parts {
    builder.body(()).unwrap().into_parts().0
}

fn header(response: &Response, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

#[test]
fn a_response_to_an_allowed_origin_names_the_exact_origin_and_varies_on_it() {
    let applied = Applied::Simple(CorsRule::grant(Some(&policy(true)), CRM).unwrap());
    let mut response = StatusCode::OK.into_response();
    response
        .headers_mut()
        .insert("access-control-allow-origin", HeaderValue::from_static("*"));

    decorate(&mut response, Some(&applied));

    assert_eq!(
        header(&response, "access-control-allow-origin").as_deref(),
        Some(CRM)
    );
    assert_eq!(
        header(&response, "access-control-allow-credentials").as_deref(),
        Some("true")
    );
    assert_eq!(header(&response, VARY.as_str()).as_deref(), Some("Origin"));
    assert_eq!(header(&response, "access-control-max-age"), None);
}

#[test]
fn credentials_are_not_announced_when_the_policy_forbids_them_and_an_upstream_claim_is_removed() {
    let applied = Applied::Simple(CorsRule::grant(Some(&policy(false)), CRM).unwrap());
    let mut response = StatusCode::OK.into_response();
    response.headers_mut().insert(
        "access-control-allow-credentials",
        HeaderValue::from_static("true"),
    );

    decorate(&mut response, Some(&applied));

    assert_eq!(header(&response, "access-control-allow-credentials"), None);
}

#[test]
fn a_response_without_a_grant_is_left_alone() {
    let mut response = StatusCode::OK.into_response();

    decorate(&mut response, None);

    assert!(response.headers().is_empty());
}

#[test]
fn an_allowed_preflight_adds_the_methods_headers_and_max_age() {
    let granted = CorsRule::preflight(
        Some(&policy(true)),
        CRM,
        HttpMethod::Post,
        Some("content-type"),
    )
    .unwrap();
    let mut response = preflight_answer();

    decorate(&mut response, Some(&Applied::Preflight(granted)));

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        header(&response, "access-control-allow-methods").as_deref(),
        Some("GET, POST")
    );
    assert_eq!(
        header(&response, "access-control-allow-headers").as_deref(),
        Some("Content-Type")
    );
    assert_eq!(
        header(&response, "access-control-max-age").as_deref(),
        Some("300")
    );
    assert_eq!(response.headers().get_all(VARY).iter().count(), 2);
}

#[test]
fn a_preflight_needs_an_origin_and_a_requested_method() {
    let both = parts(
        Request::options("/x")
            .header(ORIGIN, CRM)
            .header("access-control-request-method", "POST"),
    );
    let no_method = parts(Request::options("/x").header(ORIGIN, CRM));
    let no_origin = parts(Request::options("/x").header("access-control-request-method", "POST"));

    assert_eq!(preflight_request(&both.headers), Some((CRM, "POST")));
    assert_eq!(preflight_request(&no_method.headers), None);
    assert_eq!(preflight_request(&no_origin.headers), None);
}

#[test]
fn the_own_origin_is_https_and_the_host_unless_the_target_names_a_scheme() {
    let plain = parts(Request::get("/x").header(HOST, "api.example.test:8443"));
    let absolute = parts(Request::get("http://gw.example.test/x"));

    assert_eq!(own_origin(&plain), "https://api.example.test:8443");
    assert_eq!(own_origin(&absolute), "http://gw.example.test");
}

#[test]
fn a_websocket_upgrade_is_found_in_a_list_of_protocols_in_any_case() {
    let upgrade = parts(Request::get("/x").header(UPGRADE, "h2c, WebSocket"));
    let other = parts(Request::get("/x").header(UPGRADE, "h2c"));
    let none = parts(Request::get("/x"));

    assert!(is_websocket_upgrade(&upgrade.headers));
    assert!(!is_websocket_upgrade(&other.headers));
    assert!(!is_websocket_upgrade(&none.headers));
}

#[test]
fn a_policy_without_allowed_headers_adds_no_allow_headers_to_a_preflight() {
    let policy = CorsPolicy::new(CorsDraft {
        origins: vec![CRM.to_owned()],
        methods: vec![HttpMethod::Post],
        headers: Vec::new(),
        allow_credentials: false,
        max_age_seconds: 300,
    })
    .unwrap();
    let granted = CorsRule::preflight(Some(&policy), CRM, HttpMethod::Post, None).unwrap();
    let mut response = preflight_answer();

    decorate(&mut response, Some(&Applied::Preflight(granted)));

    assert_eq!(header(&response, "access-control-allow-headers"), None);
    assert_eq!(
        header(&response, "access-control-allow-methods").as_deref(),
        Some("POST")
    );
}

#[test]
fn every_cors_header_of_an_upstream_is_removed_even_without_a_grant() {
    let mut response = StatusCode::OK.into_response();
    for name in [
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-expose-headers",
        "access-control-max-age",
    ] {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static("x"));
    }

    decorate(&mut response, None);

    assert!(response.headers().is_empty());
}

#[test]
fn a_route_with_a_policy_varies_on_origin_when_no_grant_applies() {
    let mut response = StatusCode::OK.into_response();
    response
        .headers_mut()
        .insert("access-control-allow-origin", HeaderValue::from_static("*"));
    response.headers_mut().insert(
        "access-control-expose-headers",
        HeaderValue::from_static("x-secret"),
    );

    decorate(&mut response, Some(&Applied::Withheld));

    assert_eq!(header(&response, "access-control-allow-origin"), None);
    assert_eq!(header(&response, "access-control-expose-headers"), None);
    assert_eq!(header(&response, VARY.as_str()).as_deref(), Some("Origin"));
}

#[test]
fn an_upstream_expose_headers_claim_is_removed_from_a_granted_response() {
    let applied = Applied::Simple(CorsRule::grant(Some(&policy(true)), CRM).unwrap());
    let mut response = StatusCode::OK.into_response();
    response.headers_mut().insert(
        "access-control-expose-headers",
        HeaderValue::from_static("x-secret"),
    );

    decorate(&mut response, Some(&applied));

    assert_eq!(header(&response, "access-control-expose-headers"), None);
}
