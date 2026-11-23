use std::collections::BTreeMap;
use std::time::SystemTime;

use super::SubjectPolicy;
use crate::policy::compiled_role_set::CompiledRoleSet;
use crate::policy::decision_policy::RoleAssignment;
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::identifier::RoleId;
use crate::value_object::log_epoch::LogEpoch;
use crate::value_object::policy_digest_value::PolicyDigestValue;
use crate::value_object::policy_epoch::PolicyEpoch;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::relay_epoch::RelayEpoch;

const ROLE: &str = "0198d1a0-0000-7000-8000-000000000001";

fn epoch(version: i64) -> PolicyEpoch {
    PolicyEpoch::new(
        PolicyVersion::new(version).unwrap(),
        PolicyDigestValue::new(&[1; PolicyDigestValue::LENGTH]).unwrap(),
        LogEpoch::new(0).unwrap(),
        RelayEpoch::new(0).unwrap(),
        0,
    )
    .unwrap()
}

#[test]
fn the_policy_keeps_its_stamp_assignments_and_role_sets() {
    let role = RoleId::parse(ROLE).unwrap();
    let assignment =
        RoleAssignment::new(role, AssignmentScope::Global, Some(SystemTime::UNIX_EPOCH));
    let sets = BTreeMap::from([(role, CompiledRoleSet::default())]);

    let policy = SubjectPolicy::new(epoch(4), vec![assignment], sets.clone());

    assert_eq!(policy.epoch(), epoch(4));
    assert_eq!(policy.policy_version().value(), 4);
    assert_eq!(policy.assignments(), &[assignment]);
    assert_eq!(policy.role_sets(), &sets);
}
