use rstest::rstest;

use super::HttpMethod;

#[rstest]
#[case("GET", HttpMethod::Get)]
#[case("HEAD", HttpMethod::Head)]
#[case("POST", HttpMethod::Post)]
#[case("PUT", HttpMethod::Put)]
#[case("PATCH", HttpMethod::Patch)]
#[case("DELETE", HttpMethod::Delete)]
#[case("OPTIONS", HttpMethod::Options)]
fn a_method_round_trips_through_its_upper_case_name(
    #[case] text: &str,
    #[case] method: HttpMethod,
) {
    assert_eq!(HttpMethod::parse(text), Some(method));
    assert_eq!(method.as_str(), text);
    assert_eq!(method.to_string(), text);
}

#[rstest]
#[case("")]
#[case("get")]
#[case("TRACE")]
#[case("CONNECT")]
#[case("*")]
fn rejects_any_other_text(#[case] text: &str) {
    assert_eq!(HttpMethod::parse(text), None);
}
