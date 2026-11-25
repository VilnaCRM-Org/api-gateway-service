use rstest::rstest;

use super::{CsrfRequest, CsrfRule, origin_of_referer};
use crate::value_object::http_method::HttpMethod;

const OWN: &str = "https://api.example.test";
const CRM: &str = "https://crm.example.test";

fn request() -> CsrfRequest<'static> {
    CsrfRequest {
        method: HttpMethod::Post,
        websocket_upgrade: false,
        cookie_authenticated: true,
        origin: None,
        referer: None,
        own_origin: OWN,
    }
}

fn allowed() -> Vec<String> {
    vec![CRM.to_owned()]
}

#[rstest]
#[case::own_origin(Some(OWN), None, true)]
#[case::own_origin_in_another_case(Some("https://API.example.test"), None, true)]
#[case::allowed_origin(Some(CRM), None, true)]
#[case::foreign_origin(Some("https://evil.example.test"), None, false)]
#[case::null_origin(Some("null"), None, false)]
#[case::neither(None, None, false)]
#[case::own_referer(None, Some("https://api.example.test/page?x=1"), true)]
#[case::allowed_referer(None, Some("https://crm.example.test/app#top"), true)]
#[case::foreign_referer(None, Some("https://evil.example.test/page"), false)]
#[case::unparsable_referer(None, Some("not a url"), false)]
#[case::origin_wins_over_referer(Some("https://evil.example.test"), Some(OWN), false)]
fn a_cookie_authenticated_post_needs_an_own_or_allowed_source(
    #[case] origin: Option<&str>,
    #[case] referer: Option<&str>,
    #[case] admitted: bool,
) {
    let request = CsrfRequest {
        origin,
        referer,
        ..request()
    };

    assert_eq!(CsrfRule::admits(&request, &allowed()), admitted);
}

#[rstest]
#[case(HttpMethod::Post)]
#[case(HttpMethod::Put)]
#[case(HttpMethod::Patch)]
#[case(HttpMethod::Delete)]
fn every_unsafe_method_is_checked(#[case] method: HttpMethod) {
    let request = CsrfRequest {
        method,
        ..request()
    };

    assert!(!CsrfRule::admits(&request, &allowed()));
}

#[rstest]
#[case(HttpMethod::Get)]
#[case(HttpMethod::Head)]
#[case(HttpMethod::Options)]
fn a_safe_method_is_not_checked(#[case] method: HttpMethod) {
    let request = CsrfRequest {
        method,
        ..request()
    };

    assert!(CsrfRule::admits(&request, &allowed()));
}

#[test]
fn a_websocket_upgrade_is_checked_although_its_method_is_safe() {
    let upgrade = CsrfRequest {
        method: HttpMethod::Get,
        websocket_upgrade: true,
        origin: Some("https://evil.example.test"),
        ..request()
    };

    assert!(!CsrfRule::admits(&upgrade, &allowed()));
    assert!(CsrfRule::admits(
        &CsrfRequest {
            origin: Some(CRM),
            ..upgrade
        },
        &allowed()
    ));
}

#[test]
fn a_request_authenticated_by_a_bearer_header_is_exempt() {
    let request = CsrfRequest {
        cookie_authenticated: false,
        origin: Some("https://evil.example.test"),
        ..request()
    };

    assert!(CsrfRule::admits(&request, &allowed()));
}

#[rstest]
#[case("https://a.test/x/y", Some("https://a.test"))]
#[case("https://a.test", Some("https://a.test"))]
#[case("https://a.test:8443?q=1", Some("https://a.test:8443"))]
#[case("  https://a.test/x ", Some("https://a.test"))]
#[case("://a.test", None)]
#[case("https:///x", None)]
#[case("a.test/x", None)]
fn the_origin_of_a_referer_is_its_scheme_and_authority(
    #[case] referer: &str,
    #[case] expected: Option<&str>,
) {
    assert_eq!(origin_of_referer(referer), expected);
}
