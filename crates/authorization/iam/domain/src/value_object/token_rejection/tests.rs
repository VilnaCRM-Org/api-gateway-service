use rstest::rstest;

use super::TokenRejection;
use crate::value_object::decision_reason::DecisionReason;

#[rstest]
#[case(
    TokenRejection::Missing,
    "token_missing",
    "no credential was presented"
)]
#[case(TokenRejection::Invalid, "token_invalid", "the credential is invalid")]
#[case(TokenRejection::Expired, "token_expired", "the credential has expired")]
#[case(TokenRejection::Revoked, "token_revoked", "the credential was revoked")]
#[case(
    TokenRejection::Unavailable,
    "unavailable",
    "the credential could not be checked"
)]
fn exposes_its_reason_code_and_message(
    #[case] rejection: TokenRejection,
    #[case] code: &str,
    #[case] message: &str,
) {
    assert_eq!(rejection.code(), code);
    assert_eq!(rejection.to_string(), message);
}

#[rstest]
#[case(TokenRejection::Missing, DecisionReason::TokenMissing)]
#[case(TokenRejection::Invalid, DecisionReason::TokenInvalid)]
#[case(TokenRejection::Expired, DecisionReason::TokenExpired)]
#[case(TokenRejection::Revoked, DecisionReason::TokenRevoked)]
#[case(TokenRejection::Unavailable, DecisionReason::Unavailable)]
fn maps_to_the_decision_reason_with_the_same_code(
    #[case] rejection: TokenRejection,
    #[case] reason: DecisionReason,
) {
    assert_eq!(DecisionReason::from(rejection), reason);
    assert_eq!(reason.as_str(), rejection.code());
}
