//! `ValkeyRateLimitStore` against the compose Valkey (Story 12.2): the GCRA decisions of the
//! script, the key and its expiry, and the reload of a script that Valkey lost.

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use iam_domain::{
    RateDecision, RateDecisionRule, RateKey, RateKeyKind, RateKeyParts, RateLimitStore as _,
    RatePolicyId,
};
use iam_infrastructure::{Sha256RequestDigester, ValkeyEndpoint, ValkeyRateLimitStore};
use shared_domain::UuidGenerator as _;
use shared_infrastructure::id::UuidV7Generator;

#[expect(
    clippy::disallowed_methods,
    reason = "the test stack is described by the environment"
)]
fn stack_variable(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} is not set; run the tests through `make`"))
}

fn url() -> String {
    stack_variable("RATE_LIMIT_STORE_URL")
}

fn store() -> ValkeyRateLimitStore {
    ValkeyRateLimitStore::new(ValkeyEndpoint::parse(&url()).unwrap())
}

async fn valkey() -> redis::aio::MultiplexedConnection {
    redis::Client::open(url())
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap()
}

fn policy() -> RatePolicyId {
    RatePolicyId::from_uuid(UuidV7Generator.generate())
}

fn key(ip: &str) -> RateKey {
    let parts = RateKeyParts {
        ip: Some(ip),
        ..RateKeyParts::default()
    };
    RateKey::new(RateKeyKind::Ip, &parts, &Sha256RequestDigester).unwrap()
}

async fn expiry_millis(policy: &RatePolicyId, key: &RateKey) -> i64 {
    let mut connection = valkey().await;
    redis::cmd("PTTL")
        .arg(ValkeyRateLimitStore::key_of(policy, key))
        .query_async(&mut connection)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_request_over_the_steady_rate_is_rejected_until_one_interval_has_passed() {
    let store = store();
    let (policy, key) = (policy(), key("203.0.113.10"));
    let rule = RateDecisionRule::new(10, Duration::from_secs(1), 0);

    let first = store.check(&policy, &key, &rule).await.unwrap();
    let second = store.check(&policy, &key, &rule).await.unwrap();
    tokio::time::sleep(Duration::from_millis(120)).await;
    let third = store.check(&policy, &key, &rule).await.unwrap();

    assert_eq!(first, RateDecision::Admit);
    let RateDecision::Reject { retry_after } = second else {
        panic!("the second request must be rejected, got {second:?}");
    };
    assert!(retry_after > Duration::ZERO && retry_after <= Duration::from_millis(100));
    assert_eq!(third, RateDecision::Admit);
}

#[tokio::test]
async fn a_burst_is_admitted_above_the_steady_rate_and_then_rejected() {
    let store = store();
    let (policy, key) = (policy(), key("203.0.113.11"));
    let rule = RateDecisionRule::new(1, Duration::from_mins(1), 2);

    let mut decisions = Vec::new();
    for _ in 0..4 {
        decisions.push(store.check(&policy, &key, &rule).await.unwrap());
    }

    assert!(decisions[..3].iter().all(|decision| decision.is_admitted()));
    let RateDecision::Reject { retry_after } = decisions[3] else {
        panic!("the fourth request must be rejected");
    };
    assert!(retry_after > Duration::ZERO && retry_after <= Duration::from_mins(1));
}

#[tokio::test]
async fn the_counters_of_two_keys_and_two_policies_are_independent() {
    let store = store();
    let (first, second) = (policy(), policy());
    let rule = RateDecisionRule::new(1, Duration::from_mins(1), 0);

    let one = store
        .check(&first, &key("203.0.113.12"), &rule)
        .await
        .unwrap();
    let other_key = store
        .check(&first, &key("203.0.113.13"), &rule)
        .await
        .unwrap();
    let other_policy = store
        .check(&second, &key("203.0.113.12"), &rule)
        .await
        .unwrap();
    let again = store
        .check(&first, &key("203.0.113.12"), &rule)
        .await
        .unwrap();

    assert!(one.is_admitted() && other_key.is_admitted() && other_policy.is_admitted());
    assert!(!again.is_admitted());
}

#[tokio::test]
async fn a_counter_is_one_key_of_the_policy_and_the_key_hash_that_expires_with_its_period() {
    let store = store();
    let (policy, key) = (policy(), key("203.0.113.14"));
    let rule = RateDecisionRule::new(1, Duration::from_secs(30), 0);

    store.check(&policy, &key, &rule).await.unwrap();

    let name = ValkeyRateLimitStore::key_of(&policy, &key);
    assert_eq!(name, format!("rl:{policy}:{}", key.key_hash()));
    assert!(!name.contains("203.0.113.14"));
    let expiry = expiry_millis(&policy, &key).await;
    assert!((1..=30_001).contains(&expiry), "expiry of {expiry} ms");
}

#[tokio::test]
async fn a_script_that_valkey_lost_is_loaded_again_and_the_request_is_decided_normally() {
    let store = store();
    let (policy, key) = (policy(), key("203.0.113.15"));
    let rule = RateDecisionRule::new(1, Duration::from_mins(1), 0);
    assert_eq!(
        store.check(&policy, &key, &rule).await.unwrap(),
        RateDecision::Admit
    );
    let mut connection = valkey().await;
    let flushed: String = redis::cmd("SCRIPT")
        .arg("FLUSH")
        .query_async(&mut connection)
        .await
        .unwrap();

    let after = store.check(&policy, &key, &rule).await.unwrap();

    assert_eq!(flushed, "OK");
    assert!(
        matches!(after, RateDecision::Reject { .. }),
        "the counter survives the flush, got {after:?}"
    );
    let fresh = store
        .check(&policy, &self::key("203.0.113.16"), &rule)
        .await
        .unwrap();
    assert_eq!(fresh, RateDecision::Admit);
}

/// A server that answers every command with an error reply, and the number of connections it took.
#[expect(
    clippy::disallowed_methods,
    reason = "an integration test serves its fake Valkey on a free loopback port"
)]
fn erroring_server() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&connections);
    drop(std::thread::spawn(move || {
        for stream in listener.incoming().map_while(Result::ok) {
            counted.fetch_add(1, Ordering::SeqCst);
            drop(std::thread::spawn(move || answer_with_errors(stream)));
        }
    }));
    (port, connections)
}

/// Replies `-ERR` once per command of each chunk, a command being an array that starts a line.
fn answer_with_errors(mut stream: TcpStream) {
    let mut buffer = [0_u8; 4096];
    while let Ok(read @ 1..) = stream.read(&mut buffer) {
        let text = String::from_utf8_lossy(buffer.get(..read).unwrap_or_default());
        let commands = text
            .split("\r\n")
            .filter(|line| line.starts_with('*'))
            .count();
        if stream
            .write_all("-ERR boom\r\n".repeat(commands).as_bytes())
            .is_err()
        {
            return;
        }
    }
}

#[tokio::test]
async fn a_call_that_fails_on_a_kept_connection_drops_it_and_the_next_call_reconnects() {
    let (port, connections) = erroring_server();
    let store = ValkeyRateLimitStore::new(
        ValkeyEndpoint::parse(&format!("redis://127.0.0.1:{port}")).unwrap(),
    );
    let rule = RateDecisionRule::new(10, Duration::from_secs(1), 0);

    let first = store.check(&policy(), &key("198.51.100.1"), &rule).await;
    let second = store.check(&policy(), &key("198.51.100.1"), &rule).await;

    assert!(first.is_err());
    assert!(second.is_err());
    assert_eq!(connections.load(Ordering::SeqCst), 2);
}
