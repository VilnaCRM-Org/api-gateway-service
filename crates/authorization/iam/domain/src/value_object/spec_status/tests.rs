use rstest::rstest;

use super::SpecStatus;

#[rstest]
#[case(SpecStatus::Draft, "draft")]
#[case(SpecStatus::Active, "active")]
#[case(SpecStatus::Retired, "retired")]
fn a_status_round_trips_through_its_text_form(#[case] status: SpecStatus, #[case] text: &str) {
    assert_eq!(status.as_str(), text);
    assert_eq!(status.to_string(), text);
    assert_eq!(SpecStatus::parse(text), Some(status));
}

#[rstest]
#[case("")]
#[case("Draft")]
#[case("ACTIVE")]
#[case("deleted")]
fn any_other_text_is_not_a_status(#[case] text: &str) {
    assert_eq!(SpecStatus::parse(text), None);
}
