use rstest::rstest;

use super::RoleKind;
use crate::error::InvalidRole;

#[rstest]
#[case(RoleKind::System, "system")]
#[case(RoleKind::Custom, "custom")]
fn the_text_form_round_trips(#[case] kind: RoleKind, #[case] text: &str) {
    assert_eq!(kind.as_str(), text);
    assert_eq!(kind.to_string(), text);
    assert_eq!(RoleKind::parse(text), Ok(kind));
}

#[rstest]
#[case::empty("")]
#[case::upper_case("System")]
#[case::unknown("builtin")]
fn rejects_any_other_text(#[case] text: &str) {
    assert_eq!(RoleKind::parse(text), Err(InvalidRole::Kind));
}
