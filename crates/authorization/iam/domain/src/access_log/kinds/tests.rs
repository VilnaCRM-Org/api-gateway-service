use rstest::rstest;

use super::{AccessClass, AccessDecision, AccessLane};
use crate::value_object::decision::Decision;
use crate::value_object::decision_reason::DecisionReason;

#[rstest]
#[case(AccessLane::Access, "access")]
#[case(AccessLane::Audit, "audit")]
fn a_lane_has_its_label_value(#[case] lane: AccessLane, #[case] expected: &str) {
    assert_eq!(lane.as_str(), expected);
}

#[rstest]
#[case(AccessClass::Allow, "allow")]
#[case(AccessClass::Error, "error")]
#[case(AccessClass::Audit, "audit")]
fn a_class_has_its_metric_value(#[case] class: AccessClass, #[case] expected: &str) {
    assert_eq!(class.as_str(), expected);
}

#[rstest]
#[case(Decision::Allow, DecisionReason::Allowed, 200, AccessDecision::Allow)]
#[case(Decision::Allow, DecisionReason::Allowed, 404, AccessDecision::Allow)]
#[case(Decision::Allow, DecisionReason::Allowed, 502, AccessDecision::Error)]
#[case(
    Decision::Deny,
    DecisionReason::PermissionMissing,
    403,
    AccessDecision::Deny
)]
#[case(
    Decision::Deny,
    DecisionReason::TokenInvalid,
    401,
    AccessDecision::Deny
)]
#[case(
    Decision::Deny,
    DecisionReason::Unavailable,
    503,
    AccessDecision::Error
)]
#[case(
    Decision::Deny,
    DecisionReason::AuditModeWouldDeny,
    200,
    AccessDecision::Deny
)]
fn a_decision_kind_follows_the_reason_and_the_status(
    #[case] decision: Decision,
    #[case] reason: DecisionReason,
    #[case] status: u16,
    #[case] expected: AccessDecision,
) {
    assert_eq!(AccessDecision::of(decision, reason, status), expected);
}

#[rstest]
#[case(AccessDecision::Allow, "allow")]
#[case(AccessDecision::Deny, "deny")]
#[case(AccessDecision::Error, "error")]
fn a_decision_kind_has_its_label_value(#[case] kind: AccessDecision, #[case] expected: &str) {
    assert_eq!(kind.as_str(), expected);
}
