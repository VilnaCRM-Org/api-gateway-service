use rstest::rstest;

use super::ConfigGates;

#[rstest]
#[case::enforce(ConfigGates::Enforce, "enforce")]
#[case::relaxed(ConfigGates::Relaxed, "relaxed")]
fn a_gate_has_the_identifier_of_its_variable_value(
    #[case] gates: ConfigGates,
    #[case] identifier: &str,
) {
    assert_eq!(gates.identifier(), identifier);
}
