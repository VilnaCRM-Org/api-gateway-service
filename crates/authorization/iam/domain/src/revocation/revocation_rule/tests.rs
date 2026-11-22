use std::time::{Duration, SystemTime};

use proptest::prelude::*;
use rstest::rstest;
use shared_domain::Uuid;

use super::{RevocationRule, RevocationStatus};
use crate::value_object::access_token::{AccessToken, AccessTokenParts};
use crate::value_object::session_id::SessionId;
use crate::value_object::subject::SubjectId;
use crate::value_object::token_id::TokenId;
use crate::value_object::token_identity::TokenIdentity;
use crate::value_object::token_rejection::TokenRejection;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn issued_at(seconds: u64) -> TokenIdentity {
    TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap()),
        session: Some(SessionId::new("session-1").unwrap()),
        token_id: TokenId::new("jti-1").unwrap(),
        roles: Vec::new(),
        issued_at: at(seconds),
        expires_at: at(seconds.saturating_add(900)),
    }))
}

#[test]
fn a_token_without_revocation_state_is_accepted() {
    assert_eq!(
        RevocationRule::check(&issued_at(1_000), &RevocationStatus::default()),
        Ok(())
    );
}

#[test]
fn a_token_of_a_revoked_session_is_revoked() {
    let status = RevocationStatus {
        session_revoked: true,
        ..RevocationStatus::default()
    };

    assert_eq!(
        RevocationRule::check(&issued_at(1_000), &status),
        Err(TokenRejection::Revoked)
    );
}

#[rstest]
#[case(999, Ok(()))]
#[case(1_000, Err(TokenRejection::Revoked))]
#[case(1_001, Err(TokenRejection::Revoked))]
fn the_user_cutoff_refuses_tokens_issued_at_or_before_it(
    #[case] cutoff: u64,
    #[case] expected: Result<(), TokenRejection>,
) {
    let status = RevocationStatus {
        user_cutoff: Some(at(cutoff)),
        ..RevocationStatus::default()
    };

    assert_eq!(RevocationRule::check(&issued_at(1_000), &status), expected);
}

#[rstest]
#[case(999, Ok(()))]
#[case(1_000, Err(TokenRejection::Revoked))]
#[case(1_001, Err(TokenRejection::Revoked))]
fn the_global_cutoff_refuses_tokens_issued_at_or_before_it(
    #[case] cutoff: u64,
    #[case] expected: Result<(), TokenRejection>,
) {
    let status = RevocationStatus {
        global_cutoff: Some(at(cutoff)),
        ..RevocationStatus::default()
    };

    assert_eq!(RevocationRule::check(&issued_at(1_000), &status), expected);
}

proptest! {
    #[test]
    fn a_token_is_accepted_exactly_when_it_was_issued_after_both_cutoffs(
        iat in 0_u64..10_000,
        user in proptest::option::of(0_u64..10_000),
        global in proptest::option::of(0_u64..10_000),
    ) {
        let status = RevocationStatus {
            session_revoked: false,
            user_cutoff: user.map(at),
            global_cutoff: global.map(at),
        };
        let after_both = user.is_none_or(|cutoff| iat > cutoff) && global.is_none_or(|cutoff| iat > cutoff);

        prop_assert_eq!(RevocationRule::check(&issued_at(iat), &status).is_ok(), after_both);
    }
}
