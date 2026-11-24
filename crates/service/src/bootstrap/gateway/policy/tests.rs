use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use iam_domain::{
    PolicyDigestValue, PolicyLogTailError, PolicyTailLog, PolicyVersion, PolicyView as _,
    TailBatch, Violation,
};
use test_support::anti_entropy::{HashDigest, TextHeadCodec};
use test_support::boot_clock::FakeBootClock;
use test_support::clock::FixedClock;
use test_support::policy_bootstrap_log::{FakePolicyBootstrapLog, framed_row};
use test_support::policy_tail_log::{FakePolicyTailLog, PollStep, batch, timed};
use test_support::rng::FakeRng;
use test_support::topic_inspector::FakeTopicInspector;
use tokio::sync::watch;

use super::{BOOTSTRAP_TASK, PolicyAdapters, TailAdapters, TailSettings, start_policy};
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

/// A tail whose task panics on the first poll.
#[derive(Debug)]
struct PanickingTail;

#[async_trait::async_trait]
impl PolicyTailLog for PanickingTail {
    async fn poll(&self, _position: i64) -> Result<TailBatch, PolicyLogTailError> {
        panic!("a panic injected into the tail task");
    }

    async fn close(&self) {}
}

fn following(
    adapters: PolicyAdapters,
    log: Arc<dyn PolicyTailLog>,
    inspector: FakeTopicInspector,
) -> PolicyAdapters {
    adapters.following(TailAdapters {
        log,
        inspector: Arc::new(inspector),
        clock: Arc::new(FixedClock::at(std::time::SystemTime::UNIX_EPOCH)),
        rng: Arc::new(FakeRng::seeded(7)),
        settings: TailSettings {
            retry_delay: Duration::from_millis(1),
            ready_bound: Duration::ZERO,
            hard_bound: Duration::from_secs(15),
            derived_check_interval: Duration::from_secs(1),
        },
    })
}

async fn eventually(mut done: impl FnMut() -> bool) {
    for _ in 0..500 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the condition did not come true");
}

#[tokio::test]
async fn a_topic_that_passes_its_verdict_lets_the_pod_start_and_follow_the_topic() {
    let tail = Arc::new(FakePolicyTailLog::scripted(Vec::new(), 0));
    let adapters = following(
        adapters(FakePolicyBootstrapLog::with(Vec::new())),
        Arc::<FakePolicyTailLog>::clone(&tail),
        FakeTopicInspector::passing(),
    );
    let (stop, mut tasks) = supervisor();

    let death = start_policy(&adapters, &mut tasks).unwrap();

    wait_for_snapshot(&adapters).await;
    eventually(|| !tail.positions().is_empty()).await;
    assert_eq!(tail.positions().first(), Some(&0));
    stop.send_replace(true);
    assert_eq!(tasks.stop(BOUND).await, crate::bootstrap::TaskStop::Drained);
    assert!(tokio::time::timeout(BOUND, death).await.unwrap().is_err());
    assert_eq!(tail.closes(), 1);
}

#[tokio::test]
async fn a_topic_that_breaks_a_rule_keeps_the_pod_from_starting() {
    let violation = Violation::new("cleanup.policy", "compact", "delete");
    let inspector = FakeTopicInspector::failing(vec![violation]);
    let log = FakePolicyBootstrapLog::with(Vec::new());
    let adapters = following(
        adapters(log),
        Arc::new(FakePolicyTailLog::scripted(Vec::new(), 0)),
        inspector,
    );
    let (stop, mut tasks) = supervisor();

    let death = start_policy(&adapters, &mut tasks).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(adapters.cell.current().is_none());
    stop.send_replace(true);
    assert_eq!(tasks.stop(BOUND).await, crate::bootstrap::TaskStop::Drained);
    drop(death);
}

#[tokio::test]
async fn a_fence_rebootstraps_the_pod_and_the_tail_follows_again() {
    let log = Arc::new(FakePolicyBootstrapLog::with(Vec::new()));
    let tail = Arc::new(FakePolicyTailLog::scripted(
        vec![PollStep::Batch(batch(Vec::new(), 5, 9))],
        0,
    ));
    let mut base = adapters(FakePolicyBootstrapLog::with(Vec::new()));
    base.log = Arc::<FakePolicyBootstrapLog>::clone(&log);
    let adapters = following(
        base,
        Arc::<FakePolicyTailLog>::clone(&tail),
        FakeTopicInspector::passing(),
    );
    let (stop, mut tasks) = supervisor();

    let death = start_policy(&adapters, &mut tasks).unwrap();

    eventually(|| log.captures() >= 2 && tail.positions().len() >= 2).await;
    assert_eq!(
        adapters.cell.current().unwrap().version(),
        PolicyVersion::ZERO,
        "the pod keeps serving"
    );
    stop.send_replace(true);
    assert_eq!(tasks.stop(BOUND).await, crate::bootstrap::TaskStop::Drained);
    drop(death);
}

#[tokio::test]
async fn a_panic_in_the_tail_task_ends_the_gateway() {
    let adapters = following(
        adapters(FakePolicyBootstrapLog::with(Vec::new())),
        Arc::new(PanickingTail),
        FakeTopicInspector::passing(),
    );
    let (stop, mut tasks) = supervisor();

    let death = start_policy(&adapters, &mut tasks).unwrap();

    assert_eq!(tokio::time::timeout(BOUND, death).await.unwrap(), Ok(()));
    stop.send_replace(true);
    tasks.stop(BOUND).await;
}

/// A draw that always gives the longest delay below a bound of one minute.
#[derive(Debug)]
struct LongestDraw;

impl iam_domain::Rng for LongestDraw {
    fn next_u64(&self) -> u64 {
        60_000
    }
}

/// A fence on the first poll: the position 0 lies below the partition's first offset.
fn fencing_tail() -> Arc<FakePolicyTailLog> {
    Arc::new(FakePolicyTailLog::scripted(
        vec![PollStep::Batch(batch(Vec::new(), 5, 9))],
        0,
    ))
}

#[tokio::test]
async fn a_gateway_that_stops_during_the_rebootstrap_delay_ends_without_a_death() {
    let log = Arc::new(FakePolicyBootstrapLog::with(Vec::new()));
    let tail = fencing_tail();
    let mut base = adapters(FakePolicyBootstrapLog::with(Vec::new()));
    base.log = Arc::<FakePolicyBootstrapLog>::clone(&log);
    let mut adapters = following(
        base,
        Arc::<FakePolicyTailLog>::clone(&tail),
        FakeTopicInspector::passing(),
    );
    if let Some(tail) = adapters.tail.as_mut() {
        tail.rng = Arc::new(LongestDraw);
        tail.settings.ready_bound = Duration::from_mins(1);
    }
    let (stop, mut tasks) = supervisor();

    let death = start_policy(&adapters, &mut tasks).unwrap();
    eventually(|| tail.closes() == 1).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(log.closes(), 1, "the pod waits before it rebootstraps");
    stop.send_replace(true);
    assert_eq!(tasks.stop(BOUND).await, crate::bootstrap::TaskStop::Drained);
    assert!(tokio::time::timeout(BOUND, death).await.unwrap().is_err());
}

/// A topic whose reads fail four times once the first bootstrap closed its connection, so the
/// pod starts and its first rebootstrap after a fence fails before a later one succeeds.
#[derive(Debug)]
struct FlakyBootstrapLog {
    inner: FakePolicyBootstrapLog,
    failures: AtomicUsize,
}

impl FlakyBootstrapLog {
    const FAILURES: usize = 4;

    fn refusing(&self) -> Option<PolicyLogTailError> {
        if self.inner.closes() == 0 || self.failures.load(Ordering::SeqCst) >= Self::FAILURES {
            return None;
        }
        self.failures.fetch_add(1, Ordering::SeqCst);
        Some(PolicyLogTailError::Unavailable(Box::new(
            std::io::Error::other("the flaky topic is unavailable"),
        )))
    }
}

#[async_trait::async_trait]
impl iam_domain::PolicyBootstrapLog for FlakyBootstrapLog {
    async fn stable_end(&self) -> Result<i64, PolicyLogTailError> {
        match self.refusing() {
            Some(error) => Err(error),
            None => self.inner.stable_end().await,
        }
    }

    async fn read_framed(
        &self,
        from: i64,
        up_to: i64,
    ) -> Result<Vec<iam_domain::FramedRecord>, PolicyLogTailError> {
        match self.refusing() {
            Some(error) => Err(error),
            None => self.inner.read_framed(from, up_to).await,
        }
    }

    async fn close(&self) {
        self.inner.close().await;
    }
}

#[tokio::test]
async fn a_rebootstrap_that_fails_waits_and_tries_again() {
    let log = Arc::new(FlakyBootstrapLog {
        inner: FakePolicyBootstrapLog::with(Vec::new()),
        failures: AtomicUsize::new(0),
    });
    let tail = fencing_tail();
    let mut base = adapters(FakePolicyBootstrapLog::with(Vec::new()));
    base.log = Arc::<FlakyBootstrapLog>::clone(&log);
    let adapters = following(
        base,
        Arc::<FakePolicyTailLog>::clone(&tail),
        FakeTopicInspector::passing(),
    );
    let (stop, mut tasks) = supervisor();

    let death = start_policy(&adapters, &mut tasks).unwrap();

    eventually(|| {
        log.failures.load(Ordering::SeqCst) == FlakyBootstrapLog::FAILURES
            && tail.positions().len() >= 2
    })
    .await;
    assert_eq!(
        adapters.cell.current().unwrap().version(),
        PolicyVersion::ZERO,
        "the pod keeps serving while the rebootstrap fails"
    );
    stop.send_replace(true);
    assert_eq!(tasks.stop(BOUND).await, crate::bootstrap::TaskStop::Drained);
    drop(death);
}

#[tokio::test]
async fn a_tail_whose_apply_thread_died_ends_as_not_stopped() {
    use iam_infrastructure::{PUBLISH_INTERVAL, PolicySnapshotBuilder};

    use super::super::apply_thread::ApplyThread;
    use super::{Installed, tail_loop};

    let record = framed_row(
        0,
        "role/0192f6a0-0000-7000-8000-000000000001",
        Some("a"),
        1,
        (1, 2, PolicyDigestValue::ZERO),
    );
    let tail = Arc::new(FakePolicyTailLog::scripted(
        vec![PollStep::Batch(batch(vec![timed(record, None)], 0, 1))],
        1,
    ));
    let adapters = following(
        adapters(FakePolicyBootstrapLog::with(Vec::new())),
        Arc::<FakePolicyTailLog>::clone(&tail),
        FakeTopicInspector::passing(),
    );
    let builder = PolicySnapshotBuilder::new(
        adapters.snapshot.clone(),
        Arc::clone(&adapters.cell),
        PUBLISH_INTERVAL,
    );
    let (thread, death) = ApplyThread::spawn(builder, Arc::clone(&adapters.cell)).unwrap();
    thread
        .run_on_thread(|_builder| panic!("injected panic of the apply thread"))
        .unwrap();
    tokio::time::timeout(BOUND, death).await.unwrap().unwrap();
    let (_stop, stopping) = watch::channel(false);
    let installed = Installed {
        incomplete: None,
        tail_from: 0,
        read_to: 0,
    };

    let stopped = tail_loop(
        adapters.clone(),
        adapters.tail.clone().unwrap(),
        Arc::new(thread),
        installed,
        stopping,
    )
    .await;

    assert!(!stopped);
    assert_eq!(tail.positions(), vec![0]);
}

/// A writer into a shared buffer, for the text a log line is formatted to.
#[derive(Debug, Clone, Default)]
struct Written(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Written {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn the_rebootstrap_delay_is_logged_in_milliseconds_and_capped() {
    let written = Written::default();
    let writer = written.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);

    super::log_rebootstrap_delay(Duration::from_millis(250));
    super::log_rebootstrap_delay(Duration::MAX);
    drop(guard);

    let text = String::from_utf8(
        written
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone(),
    )
    .unwrap();
    assert!(text.contains("delay_ms=250"), "{text}");
    assert!(text.contains(&format!("delay_ms={}", u64::MAX)), "{text}");
}

#[tokio::test]
async fn a_cluster_that_cannot_be_asked_is_asked_again_until_the_gateway_stops() {
    let inspector = Arc::new(FakeTopicInspector::unreachable());
    let mut adapters = following(
        adapters(FakePolicyBootstrapLog::with(Vec::new())),
        Arc::new(FakePolicyTailLog::scripted(Vec::new(), 0)),
        FakeTopicInspector::passing(),
    );
    if let Some(tail) = adapters.tail.as_mut() {
        tail.inspector = Arc::<FakeTopicInspector>::clone(&inspector);
    }
    let (stop, mut tasks) = supervisor();

    let death = start_policy(&adapters, &mut tasks).unwrap();
    eventually(|| inspector.inspections() >= 2).await;

    assert!(adapters.cell.current().is_none());
    stop.send_replace(true);
    assert_eq!(tasks.stop(BOUND).await, crate::bootstrap::TaskStop::Drained);
    drop(death);
}
