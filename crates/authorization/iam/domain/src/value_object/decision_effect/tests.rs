use rstest::rstest;

use super::DecisionEffect;

#[rstest]
#[case(DecisionEffect::Unaffected, false, false)]
#[case(DecisionEffect::Affected, true, false)]
#[case(DecisionEffect::RevocationClass, true, true)]
fn a_revocation_class_change_always_affects_decisions(
    #[case] effect: DecisionEffect,
    #[case] affects_decisions: bool,
    #[case] revocation_class: bool,
) {
    assert_eq!(effect.affects_decisions(), affects_decisions);
    assert_eq!(effect.is_revocation_class(), revocation_class);
}
