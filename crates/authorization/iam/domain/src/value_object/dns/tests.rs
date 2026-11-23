use rstest::rstest;

use super::is_label;

#[rstest]
#[case("a", true)]
#[case("core-1", true)]
#[case("0day", true)]
#[case("", false)]
#[case("-core", false)]
#[case("core-", false)]
#[case("Core", false)]
#[case("co_re", false)]
#[case("co.re", false)]
fn labels_are_lower_case_alphanumerics_with_inner_dashes(#[case] text: &str, #[case] valid: bool) {
    assert_eq!(is_label(text), valid);
}

#[test]
fn a_label_has_at_most_63_characters() {
    assert!(is_label(&"a".repeat(63)));
    assert!(!is_label(&"a".repeat(64)));
}
