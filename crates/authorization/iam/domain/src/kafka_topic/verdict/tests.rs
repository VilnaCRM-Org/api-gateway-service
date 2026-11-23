use super::{CheckSource, ConfigurationVerdict, Violation};
use crate::kafka_topic::ConfigGates;

#[test]
fn a_verdict_without_violations_passed() {
    let verdict = ConfigurationVerdict::new(ConfigGates::Enforce, Vec::new(), None);

    assert!(verdict.passed());
    assert_eq!(verdict.gates(), ConfigGates::Enforce);
    assert_eq!(verdict.describe(), "");
}

#[test]
fn a_verdict_with_violations_names_each_offending_setting() {
    let violations = vec![
        Violation::new("cleanup.policy", "compact", "delete"),
        Violation::new("allow.everyone.if.no.acl.found", "false", "true").decided_by_fallback(),
    ];

    let verdict = ConfigurationVerdict::new(
        ConfigGates::Enforce,
        violations.clone(),
        Some(CheckSource::Fallback),
    );

    assert!(!verdict.passed());
    assert_eq!(verdict.violations(), violations);
    assert_eq!(verdict.allow_everyone_source(), Some(CheckSource::Fallback));
    assert_eq!(
        verdict.describe(),
        "cleanup.policy is delete but must be compact (broker); \
         allow.everyone.if.no.acl.found is true but must be false (fallback)"
    );
}

#[test]
fn a_source_has_an_identifier() {
    assert_eq!(CheckSource::Broker.identifier(), "broker");
    assert_eq!(CheckSource::Fallback.identifier(), "fallback");
}
