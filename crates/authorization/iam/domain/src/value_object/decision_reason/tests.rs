use rstest::rstest;

use super::DecisionReason;
use crate::value_object::decision::Decision;

#[rstest]
#[case(DecisionReason::Allowed, "allowed")]
#[case(DecisionReason::TokenMissing, "token_missing")]
#[case(DecisionReason::TokenInvalid, "token_invalid")]
#[case(DecisionReason::TokenExpired, "token_expired")]
#[case(DecisionReason::TokenRevoked, "token_revoked")]
#[case(DecisionReason::UnknownService, "unknown_service")]
#[case(DecisionReason::UnknownOperation, "unknown_operation")]
#[case(DecisionReason::MalformedOperation, "malformed_operation")]
#[case(DecisionReason::PermissionMissing, "permission_missing")]
#[case(DecisionReason::ScopeMissing, "scope_missing")]
#[case(DecisionReason::LimitsExceeded, "limits_exceeded")]
#[case(DecisionReason::Unavailable, "unavailable")]
#[case(DecisionReason::AuditModeWouldDeny, "audit_mode_would_deny")]
fn prints_and_parses_its_stable_code(#[case] reason: DecisionReason, #[case] code: &str) {
    assert_eq!(reason.as_str(), code);
    assert_eq!(reason.to_string(), code);
    assert_eq!(DecisionReason::parse(code), Some(reason));
}

#[rstest]
#[case("")]
#[case("ALLOWED")]
#[case("denied")]
#[case("allowed ")]
fn rejects_an_unknown_code(#[case] code: &str) {
    assert_eq!(DecisionReason::parse(code), None);
}

#[test]
fn lists_the_twelve_response_codes_of_fr_6_in_order() {
    let codes: Vec<&str> = DecisionReason::RESPONSE_CODES
        .iter()
        .map(|reason| reason.as_str())
        .collect();

    assert_eq!(
        codes,
        [
            "allowed",
            "token_missing",
            "token_invalid",
            "token_expired",
            "token_revoked",
            "unknown_service",
            "unknown_operation",
            "malformed_operation",
            "permission_missing",
            "scope_missing",
            "limits_exceeded",
            "unavailable",
        ]
    );
}

#[test]
fn only_allowed_belongs_to_an_allow() {
    assert_eq!(DecisionReason::Allowed.decision(), Decision::Allow);
    for reason in DecisionReason::RESPONSE_CODES
        .into_iter()
        .skip(1)
        .chain([DecisionReason::AuditModeWouldDeny])
    {
        assert_eq!(reason.decision(), Decision::Deny, "{reason}");
    }
}
