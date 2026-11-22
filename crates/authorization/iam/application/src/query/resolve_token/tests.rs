use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessToken, AccessTokenParts, CallerTokenRule, Credential, ServiceName, SessionId, SubjectId,
    TokenId, TokenIdentity, TokenRejection,
};
use rstest::rstest;
use shared_domain::{Query as _, QueryHandler as _, Uuid};
use test_support::token::FakeTokenRepository;

use super::{ResolveTokenQuery, ResolveTokenQueryHandler};
use crate::error::IamError;

const CALLER_AUDIENCE: &str = "vilnacrm-iam";

fn rule() -> CallerTokenRule {
    CallerTokenRule::new(CALLER_AUDIENCE.to_owned(), Duration::from_secs(600))
}

fn identity(subject: SubjectId, audiences: &[&str], lifetime: u64) -> TokenIdentity {
    let session = match subject {
        SubjectId::User(_) => Some(SessionId::new("session-1").unwrap()),
        SubjectId::Service(_) => None,
    };
    TokenIdentity::from(
        &AccessToken::new(AccessTokenParts {
            subject,
            session,
            token_id: TokenId::new("jti-1").unwrap(),
            roles: Vec::new(),
            issued_at: SystemTime::UNIX_EPOCH,
            expires_at: SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(lifetime))
                .unwrap(),
        })
        .with_audiences(
            audiences
                .iter()
                .map(|&audience| audience.to_owned())
                .collect(),
        ),
    )
}

fn user() -> SubjectId {
    SubjectId::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap())
}

fn service() -> SubjectId {
    SubjectId::Service(ServiceName::new("billing").unwrap())
}

fn query(raw: &str) -> ResolveTokenQuery {
    ResolveTokenQuery {
        credential: Credential::new(raw.to_owned()),
    }
}

fn handler(tokens: FakeTokenRepository) -> ResolveTokenQueryHandler {
    ResolveTokenQueryHandler::new(Arc::new(tokens), rule())
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(ResolveTokenQuery::NAME, "ResolveTokenQuery");
}

#[test]
fn the_query_does_not_print_the_credential() {
    let printed = format!("{:?}", query("raw-secret-token"));

    assert!(!printed.contains("raw-secret-token"), "{printed}");
}

#[tokio::test]
async fn a_valid_user_token_resolves_to_its_principal() {
    let tokens = FakeTokenRepository::new()
        .accepting("user-token", identity(user(), &["vilnacrm-api"], 900));

    let principal = handler(tokens).handle(query("user-token")).await.unwrap();

    assert_eq!(principal.subject(), &user());
    assert_eq!(
        principal.session().map(SessionId::as_str),
        Some("session-1")
    );
    assert_eq!(principal.token_id().as_str(), "jti-1");
}

#[tokio::test]
async fn a_service_token_with_the_caller_audience_resolves_to_its_principal() {
    let tokens = FakeTokenRepository::new().accepting(
        "service-token",
        identity(service(), &["vilnacrm-api", CALLER_AUDIENCE], 600),
    );

    let principal = handler(tokens)
        .handle(query("service-token"))
        .await
        .unwrap();

    assert_eq!(principal.subject(), &service());
}

#[rstest]
#[case::without_the_caller_audience(&["vilnacrm-api"], 300)]
#[case::living_too_long(&[CALLER_AUDIENCE], 601)]
#[tokio::test]
async fn a_service_token_that_breaks_the_caller_rule_is_unauthenticated(
    #[case] audiences: &[&str],
    #[case] lifetime: u64,
) {
    let tokens = FakeTokenRepository::new()
        .accepting("service-token", identity(service(), audiences, lifetime));

    let error = handler(tokens)
        .handle(query("service-token"))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Unauthenticated));
}

#[rstest]
#[case::invalid(TokenRejection::Invalid)]
#[case::expired(TokenRejection::Expired)]
#[case::revoked(TokenRejection::Revoked)]
#[tokio::test]
async fn a_refused_credential_is_unauthenticated(#[case] rejection: TokenRejection) {
    let tokens = FakeTokenRepository::new().rejecting("bad-token", rejection);

    let error = handler(tokens)
        .handle(query("bad-token"))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Unauthenticated));
}

#[tokio::test]
async fn a_blank_credential_is_unauthenticated() {
    let error = handler(FakeTokenRepository::new())
        .handle(query(""))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Unauthenticated));
}

#[tokio::test]
async fn an_unreadable_revocation_state_is_a_storage_failure() {
    let tokens = FakeTokenRepository::new().rejecting("token", TokenRejection::Unavailable);

    let error = handler(tokens).handle(query("token")).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
