use rstest::rstest;

use super::TokenRejection;

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
