use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessToken, AccessTokenParts, Credential, ServiceName, SessionId, SubjectId, TokenId,
    TokenIdentity, TokenRejection,
};
use rstest::rstest;
use shared_domain::{Query as _, QueryHandler as _, Uuid};
use test_support::token::FakeTokenRepository;

use super::{ResolveSubjectTokenQuery, ResolveSubjectTokenQueryHandler, TokenResolution};
use crate::error::IamError;
use crate::principal::Principal;

fn identity(subject: SubjectId, audiences: &[&str], lifetime: u64) -> TokenIdentity {
    TokenIdentity::from(
        &AccessToken::new(AccessTokenParts {
            subject,
            session: Some(SessionId::new("session-1").unwrap()),
            token_id: TokenId::new("jti-1").unwrap(),
            roles: vec!["ROLE_USER".to_owned()],
            issued_at: SystemTime::UNIX_EPOCH,
            expires_at: SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(lifetime))
                .unwrap(),
        })
        .with_audiences(audiences.iter().map(|&value| value.to_owned()).collect()),
    )
}

fn user() -> SubjectId {
    SubjectId::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap())
}

fn query(raw: &str) -> ResolveSubjectTokenQuery {
    ResolveSubjectTokenQuery {
        credential: Credential::new(raw.to_owned()),
    }
}

fn handler(tokens: FakeTokenRepository) -> ResolveSubjectTokenQueryHandler {
    ResolveSubjectTokenQueryHandler::new(Arc::new(tokens))
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(ResolveSubjectTokenQuery::NAME, "ResolveSubjectTokenQuery");
}

#[test]
fn the_query_does_not_print_the_credential() {
    let printed = format!("{:?}", query("raw-secret-token"));

    assert!(!printed.contains("raw-secret-token"), "{printed}");
}

#[tokio::test]
async fn a_valid_token_resolves_to_its_principal() {
    let valid = identity(user(), &["vilnacrm-api"], 900);
    let tokens = FakeTokenRepository::new().accepting("user-token", valid.clone());

    let resolution = handler(tokens).handle(query("user-token")).await.unwrap();

    assert_eq!(
        resolution,
        TokenResolution::Resolved(Principal::from(valid))
    );
}

#[tokio::test]
async fn a_service_token_without_the_caller_audience_still_resolves() {
    let name = ServiceName::new("billing").unwrap();
    let service = identity(SubjectId::Service(name), &["vilnacrm-api"], 86_400);
    let tokens = FakeTokenRepository::new().accepting("service-token", service.clone());

    let resolution = handler(tokens)
        .handle(query("service-token"))
        .await
        .unwrap();

    assert_eq!(
        resolution,
        TokenResolution::Resolved(Principal::from(service))
    );
}

#[rstest]
#[case::invalid(TokenRejection::Invalid)]
#[case::expired(TokenRejection::Expired)]
#[case::revoked(TokenRejection::Revoked)]
#[tokio::test]
async fn a_refused_credential_is_an_unresolved_answer(#[case] rejection: TokenRejection) {
    let tokens = FakeTokenRepository::new().rejecting("bad-token", rejection);

    let resolution = handler(tokens).handle(query("bad-token")).await.unwrap();

    assert_eq!(resolution, TokenResolution::Unresolved(rejection));
}

#[tokio::test]
async fn a_blank_credential_is_unresolved_as_missing() {
    let resolution = handler(FakeTokenRepository::new())
        .handle(query(""))
        .await
        .unwrap();

    assert_eq!(
        resolution,
        TokenResolution::Unresolved(TokenRejection::Missing)
    );
}

#[tokio::test]
async fn an_unreadable_revocation_state_is_a_storage_failure() {
    let tokens = FakeTokenRepository::new().rejecting("token", TokenRejection::Unavailable);

    let error = handler(tokens).handle(query("token")).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
