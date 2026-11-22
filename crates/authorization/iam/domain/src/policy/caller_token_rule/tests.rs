use std::time::{Duration, SystemTime};

use rstest::rstest;
use shared_domain::Uuid;

use super::CallerTokenRule;
use crate::value_object::access_token::{AccessToken, AccessTokenParts};
use crate::value_object::service_name::ServiceName;
use crate::value_object::session_id::SessionId;
use crate::value_object::subject::SubjectId;
use crate::value_object::token_id::TokenId;
use crate::value_object::token_identity::TokenIdentity;
use crate::value_object::token_rejection::TokenRejection;

const CALLER_AUDIENCE: &str = "vilnacrm-iam";

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn rule() -> CallerTokenRule {
    CallerTokenRule::new(CALLER_AUDIENCE.to_owned(), Duration::from_secs(600))
}

fn identity(subject: SubjectId, audiences: &[&str], lifetime: u64) -> TokenIdentity {
    let session = match subject {
        SubjectId::User(_) => Some(SessionId::new("session-1").unwrap()),
        SubjectId::Service(_) => None,
    };
    let token = AccessToken::new(AccessTokenParts {
        subject,
        session,
        token_id: TokenId::new("jti-1").unwrap(),
        roles: Vec::new(),
        issued_at: at(1_000),
        expires_at: at(1_000_u64.checked_add(lifetime).unwrap()),
    })
    .with_audiences(
        audiences
            .iter()
            .map(|&audience| audience.to_owned())
            .collect(),
    );
    TokenIdentity::from(&token)
}

fn service() -> SubjectId {
    SubjectId::Service(ServiceName::new("billing").unwrap())
}

fn user() -> SubjectId {
    SubjectId::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap())
}

#[test]
fn the_rule_keeps_its_settings() {
    let rule = rule();

    assert_eq!(rule.audience(), CALLER_AUDIENCE);
    assert_eq!(rule.max_service_lifetime(), Duration::from_secs(600));
}

#[rstest]
#[case::exactly_the_maximum(600)]
#[case::shorter(1)]
fn a_service_token_with_the_caller_audience_and_a_short_lifetime_passes(#[case] lifetime: u64) {
    let identity = identity(service(), &["vilnacrm-api", CALLER_AUDIENCE], lifetime);

    assert_eq!(rule().check(&identity), Ok(()));
}

#[test]
fn a_service_token_without_the_caller_audience_is_invalid() {
    let identity = identity(service(), &["vilnacrm-api"], 300);

    assert_eq!(rule().check(&identity), Err(TokenRejection::Invalid));
}

#[test]
fn a_service_token_that_lives_longer_than_the_maximum_is_invalid() {
    let identity = identity(service(), &[CALLER_AUDIENCE], 601);

    assert_eq!(rule().check(&identity), Err(TokenRejection::Invalid));
}

#[rstest]
#[case::without_the_caller_audience(&["vilnacrm-api"], 900)]
#[case::with_it(&[CALLER_AUDIENCE], 900)]
fn a_user_token_passes_whatever_its_audience_and_lifetime(
    #[case] audiences: &[&str],
    #[case] lifetime: u64,
) {
    let identity = identity(user(), audiences, lifetime);

    assert_eq!(rule().check(&identity), Ok(()));
}
