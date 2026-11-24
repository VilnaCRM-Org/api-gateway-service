use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessToken, AccessTokenParts, AccessTokenVerifier, Credential, RepositoryError,
    RevocationStatus, RevocationView, SessionId, SubjectId, TokenId, TokenIdentity, TokenMemo,
    TokenRejection, TokenRepository as _,
};
use rstest::rstest;
use sha2::{Digest as _, Sha256};
use shared_domain::{Clock, Uuid};
use test_support::access_token::FakeAccessTokenVerifier;
use test_support::clock::FixedClock;
use test_support::log::LogRecorder;

use super::{CachingTokenRepository, digest};
use crate::token::moka_token_memo::{MokaTokenMemo, TokenMemoSettings};

const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";
const RAW: &str = "header.payload.signature";
const NOW: u64 = 1_800_000_000;
const ISSUED: u64 = NOW - 60;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn token() -> AccessToken {
    AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(Uuid::parse(USER).unwrap()),
        session: Some(SessionId::new("session-1").unwrap()),
        token_id: TokenId::new("token-1").unwrap(),
        roles: vec!["ROLE_USER".to_owned()],
        issued_at: at(ISSUED),
        expires_at: at(NOW + 900),
    })
}

/// A revocation view whose answer the test sets: a status, or unavailable when it holds none.
#[derive(Debug)]
struct FakeRevocationView(Mutex<Option<RevocationStatus>>);

impl Default for FakeRevocationView {
    fn default() -> Self {
        Self(Mutex::new(Some(RevocationStatus::default())))
    }
}

impl FakeRevocationView {
    fn answer(&self, status: Option<RevocationStatus>) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = status;
    }
}

#[async_trait::async_trait]
impl RevocationView for FakeRevocationView {
    async fn status(&self, _: &TokenIdentity) -> Result<RevocationStatus, RepositoryError> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .ok_or_else(|| RepositoryError::Unavailable("database down".into()))
    }
}

struct Fixture {
    verifier: Arc<FakeAccessTokenVerifier>,
    revocations: Arc<FakeRevocationView>,
    repository: CachingTokenRepository,
}

fn fixture(verifier: FakeAccessTokenVerifier) -> Fixture {
    let verifier = Arc::new(verifier);
    let revocations = Arc::new(FakeRevocationView::default());
    let clock: Arc<dyn Clock> = Arc::new(FixedClock::at(at(NOW)));
    let memo: Arc<dyn TokenMemo> = Arc::new(MokaTokenMemo::new(
        TokenMemoSettings {
            capacity: 1_000,
            max_ttl: Duration::from_mins(5),
        },
        clock,
    ));
    let verifier_port: Arc<dyn AccessTokenVerifier> =
        Arc::<FakeAccessTokenVerifier>::clone(&verifier);
    let revocation_port: Arc<dyn RevocationView> = Arc::<FakeRevocationView>::clone(&revocations);
    let repository = CachingTokenRepository::new(verifier_port, memo, revocation_port);
    Fixture {
        verifier,
        revocations,
        repository,
    }
}

fn accepting() -> Fixture {
    fixture(FakeAccessTokenVerifier::new().accepting(RAW, token()))
}

fn credential() -> Credential {
    Credential::new(RAW.to_owned())
}

#[tokio::test]
async fn a_valid_credential_resolves_to_its_identity_and_is_verified_once() {
    let fixture = accepting();

    let first = fixture.repository.resolve(&credential()).await;
    let second = fixture.repository.resolve(&credential()).await;

    assert_eq!(first, Ok(TokenIdentity::from(&token())));
    assert_eq!(second, first);
    assert_eq!(fixture.verifier.calls(), 1);
}

#[rstest]
#[case("")]
#[case("   ")]
#[tokio::test]
async fn a_blank_credential_is_missing_without_a_verification(#[case] raw: &str) {
    let fixture = accepting();

    let outcome = fixture
        .repository
        .resolve(&Credential::new(raw.to_owned()))
        .await;

    assert_eq!(outcome, Err(TokenRejection::Missing));
    assert_eq!(fixture.verifier.calls(), 0);
}

#[tokio::test]
async fn a_rejection_is_served_from_the_negative_memo() {
    let fixture = fixture(FakeAccessTokenVerifier::new().rejecting(RAW, TokenRejection::Expired));

    let first = fixture.repository.resolve(&credential()).await;
    let second = fixture.repository.resolve(&credential()).await;

    assert_eq!(first, Err(TokenRejection::Expired));
    assert_eq!(second, Err(TokenRejection::Expired));
    assert_eq!(fixture.verifier.calls(), 1);
}

#[rstest]
#[case::session(RevocationStatus { session_revoked: true, ..RevocationStatus::default() })]
#[case::user_cutoff_at_iat(RevocationStatus { user_cutoff: Some(at(ISSUED)), ..RevocationStatus::default() })]
#[case::user_cutoff_after_iat(RevocationStatus { user_cutoff: Some(at(ISSUED + 1)), ..RevocationStatus::default() })]
#[case::global_cutoff_at_iat(RevocationStatus { global_cutoff: Some(at(ISSUED)), ..RevocationStatus::default() })]
#[tokio::test]
async fn a_memoized_token_revoked_later_is_refused_without_a_new_verification(
    #[case] status: RevocationStatus,
) {
    let fixture = accepting();
    fixture.repository.resolve(&credential()).await.unwrap();

    fixture.revocations.answer(Some(status));
    let outcome = fixture.repository.resolve(&credential()).await;

    assert_eq!(outcome, Err(TokenRejection::Revoked));
    assert_eq!(fixture.verifier.calls(), 1);
}

#[tokio::test]
async fn an_unreadable_revocation_state_makes_the_check_unavailable() {
    let fixture = accepting();
    fixture.revocations.answer(None);
    let (recorder, guard) = LogRecorder::install();

    let outcome = fixture.repository.resolve(&credential()).await;
    drop(guard);

    assert_eq!(outcome, Err(TokenRejection::Unavailable));
    assert!(
        recorder
            .lines()
            .iter()
            .any(|line| line.message == "the revocation state cannot be read")
    );
}

#[tokio::test]
async fn a_key_set_change_flushes_the_memos_and_verifies_again() {
    let fixture = accepting();
    fixture.repository.resolve(&credential()).await.unwrap();

    fixture.verifier.rotate_keys();
    fixture.repository.resolve(&credential()).await.unwrap();
    fixture.repository.resolve(&credential()).await.unwrap();

    assert_eq!(fixture.verifier.calls(), 2);
}

#[test]
fn the_digest_is_the_sha256_of_the_raw_credential() {
    let expected: [u8; 32] = Sha256::digest(RAW.as_bytes()).into();

    assert_eq!(digest(&credential()).as_bytes(), &expected);
    assert_ne!(
        digest(&credential()),
        digest(&Credential::new("another".to_owned()))
    );
}

#[tokio::test]
async fn the_log_names_the_digest_and_never_the_raw_credential() {
    let fixture = accepting();
    let (recorder, guard) = LogRecorder::install();

    fixture.repository.resolve(&credential()).await.unwrap();
    drop(guard);

    let lines = format!("{:?}", recorder.lines());
    assert!(lines.contains("resolving an access token"));
    assert!(lines.contains(&digest(&credential()).prefix()));
    assert!(!lines.contains(RAW));
}

#[tokio::test]
async fn a_credential_resolved_with_another_view_is_checked_against_that_view_and_shares_the_memos()
{
    let fixture = accepting();
    let revoking = FakeRevocationView::default();
    revoking.answer(Some(RevocationStatus {
        session_revoked: true,
        ..RevocationStatus::default()
    }));

    let refused = fixture
        .repository
        .resolve_with(&revoking, &credential())
        .await;
    let accepted = fixture.repository.resolve(&credential()).await;

    assert_eq!(refused, Err(TokenRejection::Revoked));
    assert_eq!(accepted, Ok(TokenIdentity::from(&token())));
    assert_eq!(fixture.verifier.calls(), 1);
}
