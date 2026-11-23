use rstest::rstest;

use super::UpstreamName;
use crate::error::InvalidUpstream;

#[test]
fn a_service_name_is_an_upstream_name() {
    let name = UpstreamName::new("user-service").unwrap();

    assert_eq!(name.as_str(), "user-service");
    assert_eq!(name.to_string(), "user-service");
}

#[rstest]
#[case("", InvalidUpstream::NameLength)]
#[case(&"a".repeat(64), InvalidUpstream::NameLength)]
#[case("Core", InvalidUpstream::NamePattern)]
#[case("core_1", InvalidUpstream::NamePattern)]
#[case("-core", InvalidUpstream::NamePattern)]
#[case("1core", InvalidUpstream::NamePattern)]
fn an_invalid_name_is_refused(#[case] text: &str, #[case] expected: InvalidUpstream) {
    assert_eq!(UpstreamName::new(text), Err(expected));
}
