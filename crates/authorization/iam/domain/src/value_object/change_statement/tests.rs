use super::ChangeStatement;
use crate::value_object::policy_version::PolicyVersion;

#[test]
fn an_expected_policy_version_holds_only_for_that_version() {
    let statement = ChangeStatement::ExpectPolicyVersion(PolicyVersion::new(4).unwrap());

    assert!(statement.holds(PolicyVersion::new(4).unwrap()));
    assert!(!statement.holds(PolicyVersion::new(5).unwrap()));
}
