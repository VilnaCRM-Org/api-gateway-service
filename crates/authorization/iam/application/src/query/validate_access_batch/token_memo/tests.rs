use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessToken, AccessTokenParts, Credential, SessionId, SubjectId, TokenId, TokenIdentity,
    TokenRejection, TokenRepository as _,
};
use shared_domain::Uuid;
use test_support::token::FakeTokenRepository;

use super::BatchTokenMemo;

fn identity() -> TokenIdentity {
    let now = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap();
    TokenIdentity::from(
        &AccessToken::new(AccessTokenParts {
            subject: SubjectId::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap()),
            session: Some(SessionId::new("session-1").unwrap()),
            token_id: TokenId::new("jti-1").unwrap(),
            roles: vec!["ROLE_USER".to_owned()],
            issued_at: now,
            expires_at: now.checked_add(Duration::from_mins(15)).unwrap(),
        })
        .with_audiences(vec!["vilnacrm-api".to_owned()]),
    )
}

fn credential(raw: &str) -> Credential {
    Credential::new(raw.to_owned())
}

#[tokio::test]
async fn a_credential_is_resolved_once_however_often_it_is_asked() {
    let tokens = Arc::new(FakeTokenRepository::new().accepting("valid", identity()));
    let memo = BatchTokenMemo::new(Arc::<FakeTokenRepository>::clone(&tokens));

    let first = memo.resolve(&credential("valid")).await;
    let second = memo.resolve(&credential("valid")).await;

    assert_eq!(first, Ok(identity()));
    assert_eq!(second, first);
    assert_eq!(tokens.calls(), 1);
}

#[tokio::test]
async fn each_distinct_credential_is_resolved_once() {
    let tokens = Arc::new(
        FakeTokenRepository::new()
            .accepting("one", identity())
            .rejecting("two", TokenRejection::Expired),
    );
    let memo = BatchTokenMemo::new(Arc::<FakeTokenRepository>::clone(&tokens));

    for raw in ["one", "two", "one", "two", "one"] {
        let _answer = memo.resolve(&credential(raw)).await;
    }

    assert_eq!(tokens.calls(), 2);
}

#[tokio::test]
async fn a_refusal_is_remembered_with_its_reason() {
    let tokens = Arc::new(FakeTokenRepository::failing());
    let memo = BatchTokenMemo::new(Arc::<FakeTokenRepository>::clone(&tokens));

    let first = memo.resolve(&credential("any")).await;
    let second = memo.resolve(&credential("any")).await;

    assert_eq!(first, Err(TokenRejection::Unavailable));
    assert_eq!(second, first);
    assert_eq!(tokens.calls(), 1);
}

#[tokio::test]
async fn a_new_memo_asks_the_repository_again() {
    let tokens = Arc::new(FakeTokenRepository::new().accepting("valid", identity()));

    for _batch in 0..2 {
        let memo = BatchTokenMemo::new(Arc::<FakeTokenRepository>::clone(&tokens));
        let _answer = memo.resolve(&credential("valid")).await;
    }

    assert_eq!(tokens.calls(), 2);
}
