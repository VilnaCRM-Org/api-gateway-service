use rstest::rstest;

use super::WriteMode;

#[rstest]
#[case("published", Some(WriteMode::Published))]
#[case("propagated", Some(WriteMode::Propagated))]
#[case("Published", None)]
#[case("", None)]
fn a_mode_is_parsed_from_its_lower_case_name(
    #[case] text: &str,
    #[case] expected: Option<WriteMode>,
) {
    assert_eq!(WriteMode::parse(text), expected);
}

#[rstest]
#[case(WriteMode::Published)]
#[case(WriteMode::Propagated)]
fn a_mode_round_trips_through_its_name(#[case] mode: WriteMode) {
    assert_eq!(WriteMode::parse(mode.as_str()), Some(mode));
}

#[test]
fn only_the_published_mode_is_supported_before_story_13_4() {
    assert!(WriteMode::Published.is_supported());
    assert!(!WriteMode::Propagated.is_supported());
    assert_eq!(WriteMode::default(), WriteMode::Published);
}
