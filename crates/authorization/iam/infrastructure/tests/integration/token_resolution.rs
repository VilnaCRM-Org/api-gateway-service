//! `CachingTokenRepository` over `MokaTokenMemo`: the memo lifetime on the controlled `Clock`,
//! shared verification of concurrent misses, the revocation check on every call through
//! `PgRevocationView`, the negative memo under a flood of invalid tokens, the flush on a key set
//! change, and the absence of the raw credential from rows, memo keys and log lines.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessToken, AccessTokenParts, AccessTokenVerifier, ActorRef, Credential, GlobalTokenCutoff,
    RevocationRepository as _, RevocationSource, RevocationView, SessionId, SessionRevocation,
    SessionRevocationId, SubjectId, TokenId, TokenIdentity, TokenMemo, TokenRejection,
    TokenRepository as _, UserTokenCutoff,
};
use iam_infrastructure::token::caching_token_repository::digest;
use iam_infrastructure::{
    CachingTokenRepository, MokaTokenMemo, PgRevocationRepository, PgRevocationView,
    TokenMemoSettings,
};
use shared_domain::{Clock, Uuid};
use sqlx::PgPool;
use test_support::access_token::FakeAccessTokenVerifier;
use test_support::clock::ManualClock;
use test_support::log::LogRecorder;
use test_support::revocation::FakeRevocationView;

const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";
const SESSION: &str = "session-1";
const RAW: &str = "eyJhbGciOiJSUzI1NiJ9.raw-credential-payload.signature";
const NOW: u64 = 1_800_000_000;
const ISSUED: u64 = NOW - 60;
const LIFETIME: u64 = 900;
const MAX_TTL: Duration = Duration::from_mins(5);

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn user() -> Uuid {
    Uuid::parse(USER).unwrap()
}

fn token() -> AccessToken {
    AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(user()),
        session: Some(SessionId::new(SESSION).unwrap()),
        token_id: TokenId::new("token-1").unwrap(),
        roles: vec!["ROLE_ADMIN".to_owned()],
        issued_at: at(ISSUED),
        expires_at: at(ISSUED + LIFETIME),
    })
}

fn credential(raw: &str) -> Credential {
    Credential::new(raw.to_owned())
}

/// The repository under test, its verifier double and its controlled clock.
struct Fixture {
    verifier: Arc<FakeAccessTokenVerifier>,
    clock: Arc<ManualClock>,
    repository: Arc<CachingTokenRepository>,
}

fn fixture(verifier: FakeAccessTokenVerifier, revocations: Arc<dyn RevocationView>) -> Fixture {
    let verifier = Arc::new(verifier);
    let clock = Arc::new(ManualClock::at(at(NOW)));
    let memo_clock: Arc<dyn Clock> = Arc::<ManualClock>::clone(&clock);
    let memo: Arc<dyn TokenMemo> = Arc::new(MokaTokenMemo::new(
        TokenMemoSettings {
            capacity: 1_000,
            max_ttl: MAX_TTL,
        },
        memo_clock,
    ));
    let verifier_port: Arc<dyn AccessTokenVerifier> =
        Arc::<FakeAccessTokenVerifier>::clone(&verifier);
    let repository = Arc::new(CachingTokenRepository::new(
        verifier_port,
        memo,
        revocations,
    ));
    Fixture {
        verifier,
        clock,
        repository,
    }
}

fn accepting(revocations: Arc<dyn RevocationView>) -> Fixture {
    fixture(
        FakeAccessTokenVerifier::new().accepting(RAW, token()),
        revocations,
    )
}

fn unrevoked() -> Arc<dyn RevocationView> {
    Arc::new(FakeRevocationView::new())
}

#[tokio::test]
async fn a_memoized_token_is_verified_again_only_after_min_of_exp_and_the_max_ttl() {
    let fixture = accepting(unrevoked());
    // exp - now is 840 s and TOKEN_MEMO_MAX_TTL is 300 s, so the entry lives 300 s.
    let lifetime = MAX_TTL;

    for _ in 0..5 {
        fixture.repository.resolve(&credential(RAW)).await.unwrap();
    }
    fixture
        .clock
        .advance(lifetime.saturating_sub(Duration::from_secs(1)));
    fixture.repository.resolve(&credential(RAW)).await.unwrap();
    assert_eq!(fixture.verifier.calls(), 1);

    fixture.clock.advance(Duration::from_secs(1));
    fixture.repository.resolve(&credential(RAW)).await.unwrap();
    fixture.repository.resolve(&credential(RAW)).await.unwrap();
    assert_eq!(fixture.verifier.calls(), 2);
}

#[tokio::test]
async fn a_token_close_to_its_expiry_is_memoized_only_until_its_exp() {
    let short = AccessToken::new(AccessTokenParts {
        expires_at: at(NOW + 10),
        ..token_parts()
    });
    let fixture = fixture(
        FakeAccessTokenVerifier::new().accepting(RAW, short),
        unrevoked(),
    );

    fixture.repository.resolve(&credential(RAW)).await.unwrap();
    fixture.clock.advance(Duration::from_secs(9));
    fixture.repository.resolve(&credential(RAW)).await.unwrap();
    assert_eq!(fixture.verifier.calls(), 1);

    fixture.clock.advance(Duration::from_secs(1));
    fixture.repository.resolve(&credential(RAW)).await.unwrap();
    assert_eq!(fixture.verifier.calls(), 2);
}

fn token_parts() -> AccessTokenParts {
    AccessTokenParts {
        subject: SubjectId::User(user()),
        session: Some(SessionId::new(SESSION).unwrap()),
        token_id: TokenId::new("token-1").unwrap(),
        roles: vec!["ROLE_ADMIN".to_owned()],
        issued_at: at(ISSUED),
        expires_at: at(ISSUED + LIFETIME),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fifty_concurrent_checks_of_one_unmemoized_token_share_one_verification() {
    let fixture = accepting(unrevoked());

    let checks: Vec<_> = (0..50)
        .map(|_| {
            let repository = Arc::clone(&fixture.repository);
            tokio::spawn(async move { repository.resolve(&credential(RAW)).await })
        })
        .collect();
    for check in checks {
        assert_eq!(check.await.unwrap(), Ok(TokenIdentity::from(&token())));
    }

    assert_eq!(fixture.verifier.calls(), 1);
}

fn session_revocation() -> SessionRevocation {
    SessionRevocation {
        id: SessionRevocationId::parse("0190f2a8-7b3c-7d4e-8f00-000000000001").unwrap(),
        session: SessionId::new(SESSION).unwrap(),
        user: user(),
        source: RevocationSource::UserService,
        revoked_by: ActorRef::parse("system:user-service").unwrap(),
        revoked_at: at(NOW),
        prune_after: at(NOW + LIFETIME),
    }
}

fn user_cutoff(seconds: u64) -> UserTokenCutoff {
    UserTokenCutoff {
        user: user(),
        tokens_valid_after: at(seconds),
        source: RevocationSource::Operator,
        updated_at: at(NOW),
        prune_after: at(NOW + LIFETIME),
    }
}

fn global_cutoff(seconds: u64) -> GlobalTokenCutoff {
    GlobalTokenCutoff {
        tokens_valid_after: at(seconds),
        set_by: ActorRef::parse(&format!("user:{USER}")).unwrap(),
        set_at: at(NOW),
    }
}

/// A memoized token, then the revocation `revoke` recorded in PostgreSQL.
async fn revoked_after_memoizing(pool: PgPool, revoke: Revocation) {
    let store = PgRevocationRepository::new(pool.clone());
    let fixture = accepting(Arc::new(PgRevocationView::new(pool)));
    fixture.repository.resolve(&credential(RAW)).await.unwrap();

    let recorded = match revoke {
        Revocation::Session => store.revoke_session(&session_revocation()).await,
        Revocation::User(seconds) => store.set_user_cutoff(&user_cutoff(seconds)).await,
        Revocation::Global(seconds) => store.set_global_cutoff(&global_cutoff(seconds)).await,
    };
    recorded.unwrap();
    let outcome = fixture.repository.resolve(&credential(RAW)).await;

    assert_eq!(outcome, Err(TokenRejection::Revoked));
    assert_eq!(outcome.unwrap_err().code(), "token_revoked");
    assert_eq!(fixture.verifier.calls(), 1);
}

/// The revocation recorded after the token was memoized.
#[derive(Debug, Clone, Copy)]
enum Revocation {
    Session,
    User(u64),
    Global(u64),
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_memoized_token_of_a_revoked_session_is_revoked_without_a_new_verification(pool: PgPool) {
    revoked_after_memoizing(pool, Revocation::Session).await;
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_memoized_token_is_revoked_by_a_user_cutoff_at_its_iat(pool: PgPool) {
    revoked_after_memoizing(pool, Revocation::User(ISSUED)).await;
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_memoized_token_is_revoked_by_a_user_cutoff_after_its_iat(pool: PgPool) {
    revoked_after_memoizing(pool, Revocation::User(ISSUED + 1)).await;
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_memoized_token_is_revoked_by_a_global_cutoff_at_its_iat(pool: PgPool) {
    revoked_after_memoizing(pool, Revocation::Global(ISSUED)).await;
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_memoized_token_is_revoked_by_a_global_cutoff_after_its_iat(pool: PgPool) {
    revoked_after_memoizing(pool, Revocation::Global(ISSUED + 1)).await;
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_cutoff_before_the_iat_leaves_the_token_valid(pool: PgPool) {
    let store = PgRevocationRepository::new(pool.clone());
    let fixture = accepting(Arc::new(PgRevocationView::new(pool)));
    store
        .set_user_cutoff(&user_cutoff(ISSUED - 1))
        .await
        .unwrap();
    store
        .set_global_cutoff(&global_cutoff(ISSUED - 1))
        .await
        .unwrap();

    let outcome = fixture.repository.resolve(&credential(RAW)).await;

    assert_eq!(outcome, Ok(TokenIdentity::from(&token())));
}

#[tokio::test]
async fn a_flood_of_invalid_tokens_never_evicts_a_valid_entry() {
    let fixture = accepting(unrevoked());
    fixture.repository.resolve(&credential(RAW)).await.unwrap();

    for index in 0..10_050 {
        let outcome = fixture
            .repository
            .resolve(&credential(&format!("invalid-{index}")))
            .await;
        assert_eq!(outcome, Err(TokenRejection::Invalid));
    }
    let after_flood = fixture.verifier.calls();
    fixture.repository.resolve(&credential(RAW)).await.unwrap();

    assert_eq!(after_flood, 10_051);
    assert_eq!(fixture.verifier.calls(), after_flood);
}

#[tokio::test]
async fn an_invalid_token_is_verified_again_after_its_negative_entry_expires() {
    let fixture = accepting(unrevoked());
    let invalid = credential("invalid-token");

    assert_eq!(
        fixture.repository.resolve(&invalid).await,
        Err(TokenRejection::Invalid)
    );
    fixture
        .clock
        .advance(MokaTokenMemo::NEGATIVE_TTL.saturating_sub(Duration::from_secs(1)));
    assert_eq!(
        fixture.repository.resolve(&invalid).await,
        Err(TokenRejection::Invalid)
    );
    assert_eq!(fixture.verifier.calls(), 1);

    fixture.clock.advance(Duration::from_secs(1));
    assert_eq!(
        fixture.repository.resolve(&invalid).await,
        Err(TokenRejection::Invalid)
    );
    assert_eq!(fixture.verifier.calls(), 2);
}

#[tokio::test]
async fn a_key_set_change_flushes_both_memos_and_the_next_check_verifies_again() {
    let fixture = fixture(
        FakeAccessTokenVerifier::new()
            .accepting(RAW, token())
            .rejecting("expired", TokenRejection::Expired),
        unrevoked(),
    );
    fixture.repository.resolve(&credential(RAW)).await.unwrap();
    fixture
        .repository
        .resolve(&credential("expired"))
        .await
        .unwrap_err();
    assert_eq!(fixture.verifier.calls(), 2);

    fixture.verifier.rotate_keys();
    fixture.repository.resolve(&credential(RAW)).await.unwrap();
    fixture
        .repository
        .resolve(&credential("expired"))
        .await
        .unwrap_err();

    assert_eq!(fixture.verifier.calls(), 4);
}

/// Every stored revocation and inbound event as JSON text.
async fn stored_rows(pool: &PgPool) -> String {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT row_to_json(t)::text FROM iam_revoked_sessions t
        UNION ALL SELECT row_to_json(t)::text FROM iam_user_token_validity t
        UNION ALL SELECT row_to_json(t)::text FROM iam_global_token_cutoff t
        UNION ALL SELECT row_to_json(t)::text FROM iam_inbound_events t",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    rows.join("\n")
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn no_row_memo_key_or_log_line_holds_the_raw_credential_and_the_memo_holds_no_grant(
    pool: PgPool,
) {
    let store = PgRevocationRepository::new(pool.clone());
    let fixture = accepting(Arc::new(PgRevocationView::new(pool.clone())));
    let (recorder, guard) = LogRecorder::install();

    let identity = fixture.repository.resolve(&credential(RAW)).await.unwrap();
    fixture
        .repository
        .resolve(&credential(&format!("{RAW}x")))
        .await
        .unwrap_err();
    store.revoke_session(&session_revocation()).await.unwrap();
    store.set_user_cutoff(&user_cutoff(ISSUED)).await.unwrap();
    store
        .set_global_cutoff(&global_cutoff(ISSUED))
        .await
        .unwrap();
    fixture
        .repository
        .resolve(&credential(RAW))
        .await
        .unwrap_err();
    drop(guard);

    let rows = stored_rows(&pool).await;
    assert!(rows.contains(SESSION));
    assert!(!rows.contains(RAW));
    let lines = format!("{:?}", recorder.lines());
    assert!(lines.contains("resolving an access token"));
    assert!(!lines.contains(RAW));
    let key = digest(&credential(RAW));
    assert!(!format!("{key:?}").contains(RAW));
    assert_ne!(key.as_bytes().as_slice(), RAW.as_bytes());
    let memoized = format!("{identity:?}");
    assert!(!memoized.contains("ROLE_ADMIN"));
    assert!(!memoized.to_lowercase().contains("permission"));
    assert!(!memoized.to_lowercase().contains("grant"));
}
