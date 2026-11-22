use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessToken, AccessTokenParts, AccessTokenVerifier as _, Credential, SubjectId, TokenId,
    TokenRejection,
};
use shared_domain::Uuid;

use super::{DEVELOPMENT_PUBLIC_KEYS_FILE, FakeAccessTokenVerifier};

fn token() -> AccessToken {
    AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap()),
        session: None,
        token_id: TokenId::new("jti").unwrap(),
        roles: Vec::new(),
        issued_at: SystemTime::UNIX_EPOCH,
        expires_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_mins(15))
            .unwrap(),
    })
}

fn verify(fake: &FakeAccessTokenVerifier, raw: &str) -> Result<AccessToken, TokenRejection> {
    fake.verify(&Credential::new(raw.to_owned()))
}

#[test]
fn answers_from_its_table_and_counts_the_calls() {
    let fake = FakeAccessTokenVerifier::new()
        .accepting("good", token())
        .rejecting("old", TokenRejection::Expired);

    assert_eq!(verify(&fake, "good"), Ok(token()));
    assert_eq!(verify(&fake, "old"), Err(TokenRejection::Expired));
    assert_eq!(verify(&fake, "other"), Err(TokenRejection::Invalid));
    assert_eq!(verify(&fake, " "), Err(TokenRejection::Missing));
    assert_eq!(fake.calls(), 4);
}

#[test]
fn the_development_key_file_holds_one_public_key() {
    let text = std::fs::read_to_string(DEVELOPMENT_PUBLIC_KEYS_FILE).unwrap();

    assert_eq!(text.matches("-----BEGIN PUBLIC KEY-----").count(), 1);
    assert!(!text.contains("PRIVATE"));
}

#[test]
fn the_key_set_version_changes_only_when_the_keys_rotate() {
    let fake = FakeAccessTokenVerifier::new();

    assert_eq!(fake.key_set_version(), 0);
    fake.rotate_keys();
    fake.rotate_keys();
    assert_eq!(fake.key_set_version(), 2);
}
