use std::sync::Arc;
use std::time::Duration;

use iam_domain::{PolicyDigestValue, PolicyVersion, PolicyView as _};
use test_support::anti_entropy::{HashDigest, TextHeadCodec};
use test_support::boot_clock::FakeBootClock;
use test_support::policy_bootstrap_log::{FakePolicyBootstrapLog, framed_row};
use tokio::sync::watch;

use super::{BOOTSTRAP_TASK, PolicyAdapters, start_policy};
use crate::bootstrap::{TaskMode, TaskSupervisor};

const BOUND: Duration = Duration::from_secs(5);

fn adapters(log: FakePolicyBootstrapLog) -> PolicyAdapters {
    let mut adapters = PolicyAdapters::with(Arc::new(log), Arc::new(FakeBootClock::new()));
    adapters.bootstrap.codec = Arc::new(TextHeadCodec);
    adapters.bootstrap.digest = Arc::new(HashDigest);
    adapters
}

fn supervisor() -> (watch::Sender<bool>, TaskSupervisor) {
    let (stop, stopping) = watch::channel(false);
    (stop, TaskSupervisor::new(TaskMode::Test, stopping))
}

async fn wait_for_snapshot(adapters: &PolicyAdapters) {
    for _ in 0..500 {
        if adapters.cell.current().is_some() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("no snapshot was published");
}

#[tokio::test]
async fn an_empty_topic_bootstraps_the_pod_at_version_zero() {
    let adapters = adapters(FakePolicyBootstrapLog::with(Vec::new()));
    let (stop, mut tasks) = supervisor();

    let death = start_policy(&adapters, &mut tasks).unwrap();

    wait_for_snapshot(&adapters).await;
    let snapshot = adapters.cell.current().unwrap();
    assert_eq!(snapshot.version(), PolicyVersion::ZERO);
    assert_eq!(snapshot.digest(), PolicyDigestValue::ZERO);
    assert_eq!(tasks.len(), 1, "{BOOTSTRAP_TASK} runs");
    stop.send_replace(true);
    assert_eq!(tasks.stop(BOUND).await, crate::bootstrap::TaskStop::Drained);
    assert!(tokio::time::timeout(BOUND, death).await.unwrap().is_err());
}

#[tokio::test]
async fn a_topic_that_ends_in_an_incomplete_version_publishes_the_version_before_it() {
    let half_written = framed_row(
        0,
        "role/0192f6a0-0000-7000-8000-000000000001",
        Some("a"),
        1,
        (1, 2, PolicyDigestValue::ZERO),
    );
    let adapters = adapters(FakePolicyBootstrapLog::with(vec![half_written]));
    let (stop, mut tasks) = supervisor();

    let death = start_policy(&adapters, &mut tasks).unwrap();

    wait_for_snapshot(&adapters).await;
    assert_eq!(
        adapters.cell.current().unwrap().version(),
        PolicyVersion::ZERO
    );
    stop.send_replace(true);
    assert_eq!(tasks.stop(BOUND).await, crate::bootstrap::TaskStop::Drained);
    drop(death);
}

#[tokio::test]
async fn a_topic_that_cannot_be_read_leaves_the_pod_not_started() {
    let adapters = adapters(FakePolicyBootstrapLog::with(Vec::new()).unavailable());
    let (stop, mut tasks) = supervisor();

    let death = start_policy(&adapters, &mut tasks).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(adapters.cell.current().is_none());
    stop.send_replace(true);
    assert_eq!(tasks.stop(BOUND).await, crate::bootstrap::TaskStop::Drained);
    drop(death);
}

#[test]
fn the_production_wiring_opens_nothing_until_the_first_read() {
    use crate::cli::GatewayArgs;
    use test_support::access_token::DEVELOPMENT_PUBLIC_KEYS_FILE;

    let mut args = GatewayArgs::default();
    args.service.app_env = Some("test".to_owned());
    args.service.tokens.public_keys_file = Some(DEVELOPMENT_PUBLIC_KEYS_FILE.to_owned());
    args.service.kafka.bootstrap_servers = Some("localhost:1".to_owned());
    args.service.kafka.security_protocol = Some("PLAINTEXT".to_owned());
    let config = crate::config::GatewayConfig::from_args(&args).unwrap();

    let adapters = PolicyAdapters::from_config(&config);

    assert!(adapters.cell.current().is_none());
    assert!(format!("{adapters:?}").starts_with("PolicyAdapters"));
}
