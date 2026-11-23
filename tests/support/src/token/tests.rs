use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessToken, AccessTokenParts, Credential, CredentialDigest, SessionId, SubjectId, TokenId,
    TokenIdentity, TokenMemo as _, TokenRejection, TokenRepository as _,
};
use shared_domain::Uuid;

use super::{FakeTokenMemo, FakeTokenRepository};
use crate::block_on;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn identity() -> TokenIdentity {
    TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f00-123456789abc").unwrap()),
        session: Some(SessionId::new("session-1").unwrap()),
        token_id: TokenId::new("token-1").unwrap(),
        roles: Vec::new(),
        issued_at: at(1_000),
        expires_at: at(1_900),
    }))
}

const VALID: CredentialDigest = CredentialDigest::new([1; 32]);
const INVALID: CredentialDigest = CredentialDigest::new([2; 32]);

#[test]
fn an_identity_is_verified_once_and_then_served_from_the_memo() {
    let memo = FakeTokenMemo::new();
    let verify = || Ok(identity());

    let first = block_on(memo.resolve(&VALID, &verify));
    let second = block_on(memo.resolve(&VALID, &verify));

    assert_eq!(first, Ok(identity()));
    assert_eq!(second, Ok(identity()));
    assert_eq!(memo.verifications(), 1);
    assert_eq!(memo.entries(), (1, 0));
}

#[test]
fn a_rejection_is_memoized_in_the_negative_memo() {
    let memo = FakeTokenMemo::new();
    let verify = || Err(TokenRejection::Invalid);

    assert_eq!(block_on(memo.rejection(&INVALID)), None);
    assert_eq!(
        block_on(memo.resolve(&INVALID, &verify)),
        Err(TokenRejection::Invalid)
    );
    assert_eq!(
        block_on(memo.rejection(&INVALID)),
        Some(TokenRejection::Invalid)
    );
    assert_eq!(memo.entries(), (0, 1));
}

#[test]
fn a_flush_empties_both_memos_and_is_counted() {
    let memo = FakeTokenMemo::new();
    block_on(memo.resolve(&VALID, &|| Ok(identity()))).unwrap();
    block_on(memo.resolve(&INVALID, &|| Err(TokenRejection::Expired))).unwrap_err();

    block_on(memo.flush());

    assert_eq!(memo.entries(), (0, 0));
    assert_eq!(memo.flushes(), 1);
    assert_eq!(block_on(memo.rejection(&INVALID)), None);
}

#[test]
fn the_repository_answers_from_its_table_and_counts_its_calls() {
    let repository = FakeTokenRepository::new()
        .accepting("valid", identity())
        .rejecting("revoked", TokenRejection::Revoked);
    let resolve = |raw: &str| block_on(repository.resolve(&Credential::new(raw.to_owned())));

    assert_eq!(resolve("valid"), Ok(identity()));
    assert_eq!(resolve("revoked"), Err(TokenRejection::Revoked));
    assert_eq!(resolve("unknown"), Err(TokenRejection::Invalid));
    assert_eq!(resolve("  "), Err(TokenRejection::Missing));
    assert_eq!(repository.calls(), 4);
}

#[test]
fn a_failing_repository_answers_unavailable_even_for_a_registered_credential() {
    let repository = FakeTokenRepository::failing().accepting("valid", identity());
    let resolve = |raw: &str| block_on(repository.resolve(&Credential::new(raw.to_owned())));

    assert_eq!(resolve("valid"), Err(TokenRejection::Unavailable));
    assert_eq!(resolve("  "), Err(TokenRejection::Unavailable));
    assert_eq!(repository.calls(), 2);
}
