use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessToken, AccessTokenParts, CredentialDigest, SessionId, SubjectId, TokenId, TokenIdentity,
    TokenMemo as _, TokenRejection,
};
use shared_domain::{Clock, Uuid};

use super::{MokaTokenMemo, TokenMemoSettings};

const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";
const NOW: u64 = 1_800_000_000;
const MAX_TTL: Duration = Duration::from_secs(60);

/// A clock the test moves by hand.
#[derive(Debug)]
struct ManualClock(Mutex<SystemTime>);

impl ManualClock {
    fn at(time: SystemTime) -> Arc<Self> {
        Arc::new(Self(Mutex::new(time)))
    }

    fn advance(&self, by: Duration) {
        let mut now = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        *now = now.checked_add(by).unwrap();
    }
}

impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn identity(expires_at: SystemTime) -> TokenIdentity {
    TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(Uuid::parse(USER).unwrap()),
        session: Some(SessionId::new("session-1").unwrap()),
        token_id: TokenId::new("token-1").unwrap(),
        roles: vec!["ROLE_USER".to_owned()],
        issued_at: at(NOW),
        expires_at,
    }))
}

fn digest(byte: u8) -> CredentialDigest {
    CredentialDigest::new([byte; CredentialDigest::LENGTH])
}

fn memo(clock: &Arc<ManualClock>) -> MokaTokenMemo {
    let clock: Arc<dyn Clock> = Arc::<ManualClock>::clone(clock);
    MokaTokenMemo::new(
        TokenMemoSettings {
            capacity: 1_000,
            max_ttl: MAX_TTL,
        },
        clock,
    )
}

/// A verification that counts its runs and answers `outcome`.
struct Counted {
    runs: AtomicUsize,
    outcome: Result<TokenIdentity, TokenRejection>,
}

impl Counted {
    fn new(outcome: Result<TokenIdentity, TokenRejection>) -> Self {
        Self {
            runs: AtomicUsize::new(0),
            outcome,
        }
    }

    fn run(&self) -> Result<TokenIdentity, TokenRejection> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        self.outcome.clone()
    }

    fn runs(&self) -> usize {
        self.runs.load(Ordering::SeqCst)
    }
}

#[tokio::test]
async fn a_miss_verifies_once_and_a_hit_is_served_from_the_positive_memo() {
    let clock = ManualClock::at(at(NOW));
    let memo = memo(&clock);
    let expected = identity(at(NOW + 900));
    let counted = Counted::new(Ok(expected.clone()));
    let verify = || counted.run();

    assert_eq!(
        memo.resolve(&digest(1), &verify).await,
        Ok(expected.clone())
    );
    assert_eq!(memo.resolve(&digest(1), &verify).await, Ok(expected));
    assert_eq!(counted.runs(), 1);
    assert_eq!(memo.rejection(&digest(1)).await, None);
}

#[tokio::test]
async fn an_identity_is_served_until_the_max_ttl_and_verified_again_after_it() {
    let clock = ManualClock::at(at(NOW));
    let memo = memo(&clock);
    let counted = Counted::new(Ok(identity(at(NOW + 900))));
    let verify = || counted.run();

    memo.resolve(&digest(1), &verify).await.unwrap();
    clock.advance(MAX_TTL.checked_sub(Duration::from_secs(1)).unwrap());
    memo.resolve(&digest(1), &verify).await.unwrap();
    assert_eq!(counted.runs(), 1);

    clock.advance(Duration::from_secs(1));
    memo.resolve(&digest(1), &verify).await.unwrap();
    assert_eq!(counted.runs(), 2);
}

#[tokio::test]
async fn an_identity_is_served_no_longer_than_its_expiry() {
    let clock = ManualClock::at(at(NOW));
    let memo = memo(&clock);
    let counted = Counted::new(Ok(identity(at(NOW + 10))));
    let verify = || counted.run();

    memo.resolve(&digest(1), &verify).await.unwrap();
    clock.advance(Duration::from_secs(9));
    memo.resolve(&digest(1), &verify).await.unwrap();
    assert_eq!(counted.runs(), 1);

    clock.advance(Duration::from_secs(1));
    memo.resolve(&digest(1), &verify).await.unwrap();
    assert_eq!(counted.runs(), 2);
}

#[tokio::test]
async fn an_identity_already_expired_when_verified_is_not_memoized() {
    let clock = ManualClock::at(at(NOW));
    let memo = memo(&clock);
    let counted = Counted::new(Ok(identity(at(NOW))));
    let verify = || counted.run();

    memo.resolve(&digest(1), &verify).await.unwrap();
    memo.resolve(&digest(1), &verify).await.unwrap();

    assert_eq!(counted.runs(), 2);
}

#[tokio::test]
async fn a_rejection_is_memoized_for_the_negative_ttl() {
    let clock = ManualClock::at(at(NOW));
    let memo = memo(&clock);
    let counted = Counted::new(Err(TokenRejection::Invalid));
    let verify = || counted.run();

    assert_eq!(
        memo.resolve(&digest(2), &verify).await,
        Err(TokenRejection::Invalid)
    );
    assert_eq!(
        memo.rejection(&digest(2)).await,
        Some(TokenRejection::Invalid)
    );

    clock.advance(
        MokaTokenMemo::NEGATIVE_TTL
            .checked_sub(Duration::from_secs(1))
            .unwrap(),
    );
    assert_eq!(
        memo.rejection(&digest(2)).await,
        Some(TokenRejection::Invalid)
    );

    clock.advance(Duration::from_secs(1));
    assert_eq!(memo.rejection(&digest(2)).await, None);
    assert_eq!(counted.runs(), 1);
}

#[tokio::test]
async fn a_rejection_never_evicts_a_memoized_identity() {
    let clock = ManualClock::at(at(NOW));
    let memo = memo(&clock);
    let valid = Counted::new(Ok(identity(at(NOW + 900))));
    let invalid = Counted::new(Err(TokenRejection::Invalid));
    let verify_valid = || valid.run();
    let verify_invalid = || invalid.run();

    memo.resolve(&digest(1), &verify_valid).await.unwrap();
    for byte in 2..=255 {
        memo.resolve(&digest(byte), &verify_invalid)
            .await
            .unwrap_err();
    }
    memo.resolve(&digest(1), &verify_valid).await.unwrap();

    assert_eq!(valid.runs(), 1);
    assert_eq!(invalid.runs(), 254);
}

#[tokio::test]
async fn flush_drops_both_memos() {
    let clock = ManualClock::at(at(NOW));
    let memo = memo(&clock);
    let valid = Counted::new(Ok(identity(at(NOW + 900))));
    let invalid = Counted::new(Err(TokenRejection::Expired));
    let verify_valid = || valid.run();
    let verify_invalid = || invalid.run();
    memo.resolve(&digest(1), &verify_valid).await.unwrap();
    memo.resolve(&digest(2), &verify_invalid).await.unwrap_err();

    memo.flush().await;

    assert_eq!(memo.rejection(&digest(2)).await, None);
    memo.resolve(&digest(1), &verify_valid).await.unwrap();
    assert_eq!(valid.runs(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_misses_of_one_digest_share_one_verification() {
    let clock = ManualClock::at(at(NOW));
    let memo = Arc::new(memo(&clock));
    let counted = Arc::new(Counted::new(Ok(identity(at(NOW + 900)))));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..50 {
        let memo = Arc::clone(&memo);
        let counted = Arc::clone(&counted);
        tasks.spawn(async move {
            let verify = || {
                std::thread::sleep(Duration::from_millis(5));
                counted.run()
            };
            memo.resolve(&digest(7), &verify).await
        });
    }

    let outcomes = tasks.join_all().await;

    assert_eq!(outcomes.len(), 50);
    assert!(outcomes.iter().all(Result::is_ok));
    assert_eq!(counted.runs(), 1);
}

#[tokio::test]
async fn a_clock_at_the_end_of_time_bounds_entries_by_expiry_and_now() {
    let end_of_time = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(u64::try_from(i64::MAX).unwrap()))
        .unwrap();
    let clock = ManualClock::at(end_of_time);
    let memo = memo(&clock);
    let valid = Counted::new(Ok(identity(end_of_time)));
    let invalid = Counted::new(Err(TokenRejection::Invalid));
    let verify_valid = || valid.run();
    let verify_invalid = || invalid.run();

    memo.resolve(&digest(1), &verify_valid).await.unwrap();
    memo.resolve(&digest(1), &verify_valid).await.unwrap();
    memo.resolve(&digest(2), &verify_invalid).await.unwrap_err();

    assert_eq!(valid.runs(), 2);
    assert_eq!(memo.rejection(&digest(2)).await, None);
}

#[test]
fn the_debug_output_holds_counts_and_never_a_key() {
    let clock = ManualClock::at(at(NOW));
    let output = format!("{:?}", memo(&clock));

    assert!(output.starts_with("MokaTokenMemo"));
    assert!(output.contains("positive: 0"));
    assert!(output.contains("negative: 0"));
    assert!(output.contains("max_ttl: 60s"));
}
