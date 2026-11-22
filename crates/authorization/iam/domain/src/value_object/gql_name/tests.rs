use rstest::rstest;

use super::GqlName;

#[rstest]
#[case("Query")]
#[case("createRole")]
#[case("_private")]
#[case("Type2_field")]
#[case("a")]
fn accepts_a_graphql_name(#[case] text: &str) {
    let name = GqlName::parse(text).unwrap();

    assert_eq!(name.as_str(), text);
    assert_eq!(name.to_string(), text);
}

#[test]
fn accepts_a_name_of_exactly_the_maximum_length() {
    assert!(GqlName::parse(&"a".repeat(GqlName::MAX_LENGTH)).is_some());
}

#[rstest]
#[case("")]
#[case("2Type")]
#[case("__typename")]
#[case("__schema")]
#[case("with-dash")]
#[case("with.dot")]
#[case("*")]
#[case("naïve")]
fn rejects_anything_else(#[case] text: &str) {
    assert_eq!(GqlName::parse(text), None);
}

#[test]
fn rejects_a_name_over_the_maximum_length() {
    assert_eq!(GqlName::parse(&"a".repeat(GqlName::MAX_LENGTH + 1)), None);
}

#[test]
fn accepts_a_single_underscore_prefix() {
    assert!(GqlName::parse("_").is_some());
    assert!(GqlName::parse("_x").is_some());
}
