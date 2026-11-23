use rstest::rstest;

use super::RouteHost;
use crate::error::InvalidRoute;

#[rstest]
#[case("api.example.com")]
#[case("localhost")]
#[case("a-b.c1.example")]
fn a_lower_case_dns_name_is_a_host(#[case] text: &str) {
    let host = RouteHost::new(text).unwrap();

    assert_eq!(host.as_str(), text);
    assert_eq!(host.to_string(), text);
}

#[rstest]
#[case("", InvalidRoute::HostLength)]
#[case(&"a".repeat(254), InvalidRoute::HostLength)]
#[case("API.example.com", InvalidRoute::HostFormat)]
#[case("api..example.com", InvalidRoute::HostFormat)]
#[case("api.example.com.", InvalidRoute::HostFormat)]
#[case("-api.example.com", InvalidRoute::HostFormat)]
#[case("api_x.example.com", InvalidRoute::HostFormat)]
#[case("api.example.com:8080", InvalidRoute::HostFormat)]
fn an_invalid_host_is_refused(#[case] text: &str, #[case] expected: InvalidRoute) {
    assert_eq!(RouteHost::new(text), Err(expected));
}
