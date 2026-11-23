use std::sync::Arc;
use std::time::Duration;

use iam_domain::{
    EndpointConditions, EndpointListing, EndpointParts, EndpointWatch, EndpointWatchError,
    UpstreamEndpoint, WatchBatch, WatchTarget, Zone,
};
use test_support::endpoint_watch::FakeEndpointWatch;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::{EndpointWatcher, WatcherSettings};
use crate::endpoint_directory::{EndpointDirectory, EndpointView, ZoneSource};

const SETTLE: Duration = Duration::from_secs(5);

fn target() -> WatchTarget {
    WatchTarget {
        namespace: "vilnacrm".to_owned(),
        service: "user-service".to_owned(),
    }
}

fn endpoint(address: &str, conditions: EndpointConditions) -> UpstreamEndpoint {
    UpstreamEndpoint::new(EndpointParts {
        address: address.to_owned(),
        port: 8081,
        zone: Some(Zone::new("zone-a").unwrap()),
        pod: None,
        conditions,
    })
}

fn healthy(address: &str) -> UpstreamEndpoint {
    endpoint(address, EndpointConditions::healthy())
}

fn settings() -> WatcherSettings {
    WatcherSettings {
        idle_pause: Duration::from_millis(100),
        retry_pause: Duration::from_millis(100),
        list_timeout: Duration::from_secs(1),
        watch_timeout: Duration::from_secs(1),
    }
}

struct Running {
    view: EndpointView,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl Running {
    fn start(source: &Arc<FakeEndpointWatch>, targets: Vec<WatchTarget>) -> Self {
        let port: Arc<dyn EndpointWatch> = Arc::<FakeEndpointWatch>::clone(source);
        Self::start_with(port, targets)
    }

    fn start_with(port: Arc<dyn EndpointWatch>, targets: Vec<WatchTarget>) -> Self {
        let directory = Arc::new(EndpointDirectory::new(ZoneSource {
            peers: target(),
            pod: None,
            explicit: None,
        }));
        let view = directory.view();
        let (stop, shutdown) = watch::channel(false);
        let watcher = EndpointWatcher::new(port, directory, targets, settings());
        Self {
            view,
            stop,
            task: tokio::spawn(watcher.run(shutdown)),
        }
    }

    /// Lets the watcher run in virtual time.
    async fn settle() {
        tokio::time::sleep(SETTLE).await;
    }

    fn addresses(&self) -> Vec<String> {
        let mut addresses: Vec<String> = self
            .view
            .offered(&target())
            .iter()
            .map(|endpoint| endpoint.address().to_owned())
            .collect();
        addresses.sort();
        addresses
    }

    async fn stop(self) {
        self.stop.send_replace(true);
        self.task.await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn the_listed_endpoints_are_published_and_changes_follow() {
    let source = Arc::new(FakeEndpointWatch::new());
    source.set_slice(&target(), "a", vec![healthy("10.0.0.1")]);
    let running = Running::start(&source, vec![target()]);
    Running::settle().await;
    assert_eq!(running.addresses(), ["10.0.0.1"]);

    source.set_slice(
        &target(),
        "a",
        vec![healthy("10.0.0.1"), healthy("10.0.0.2")],
    );
    Running::settle().await;
    assert_eq!(running.addresses(), ["10.0.0.1", "10.0.0.2"]);

    source.set_slice(
        &target(),
        "a",
        vec![
            healthy("10.0.0.1"),
            endpoint("10.0.0.2", EndpointConditions::default()),
        ],
    );
    Running::settle().await;
    assert_eq!(running.addresses(), ["10.0.0.1"]);

    source.remove_slice(&target(), "a");
    Running::settle().await;
    assert_eq!(running.addresses().len(), 0);
    running.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_failing_source_keeps_the_last_endpoints_and_resumes_from_the_same_version() {
    let source = Arc::new(FakeEndpointWatch::new());
    source.set_slice(&target(), "a", vec![healthy("10.0.0.1")]);
    let running = Running::start(&source, vec![target()]);
    Running::settle().await;
    let version = source.watch_calls().last().unwrap().1.clone();

    source.fail_next(3);
    source.set_slice(&target(), "b", vec![healthy("10.0.0.2")]);
    Running::settle().await;

    assert_eq!(running.addresses(), ["10.0.0.1", "10.0.0.2"]);
    let resumes = source
        .watch_calls()
        .into_iter()
        .filter(|(_target, resumed)| *resumed == version)
        .count();
    assert!(resumes >= 3, "the failed calls retry from {version}");
    assert_eq!(source.list_calls().len(), 1);
    running.stop().await;
}

#[tokio::test(start_paused = true)]
async fn an_expired_version_lists_again_without_losing_an_endpoint() {
    let source = Arc::new(FakeEndpointWatch::new());
    source.set_slice(&target(), "a", vec![healthy("10.0.0.1")]);
    let running = Running::start(&source, vec![target()]);
    Running::settle().await;

    source.set_slice(&target(), "b", vec![healthy("10.0.0.2")]);
    source.expire();
    source.set_slice(&target(), "c", vec![healthy("10.0.0.3")]);
    Running::settle().await;

    assert_eq!(running.addresses(), ["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
    assert_eq!(source.list_calls().len(), 2);
    running.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_failing_list_is_retried_until_it_succeeds() {
    let source = Arc::new(FakeEndpointWatch::new());
    source.set_slice(&target(), "a", vec![healthy("10.0.0.1")]);
    source.fail_next(2);
    let running = Running::start(&source, vec![target()]);

    Running::settle().await;

    assert_eq!(running.addresses(), ["10.0.0.1"]);
    assert_eq!(source.list_calls().len(), 3);
    running.stop().await;
}

#[tokio::test(start_paused = true)]
async fn every_target_is_watched_on_its_own() {
    let source = Arc::new(FakeEndpointWatch::new());
    let other = WatchTarget {
        namespace: "vilnacrm".to_owned(),
        service: "billing".to_owned(),
    };
    source.set_slice(&target(), "a", vec![healthy("10.0.0.1")]);
    source.set_slice(&other, "a", vec![healthy("10.1.0.1")]);
    let running = Running::start(&source, vec![target(), other.clone()]);

    Running::settle().await;

    assert_eq!(running.addresses(), ["10.0.0.1"]);
    assert_eq!(running.view.offered(&other).len(), 1);
    running.stop().await;
}

#[tokio::test(start_paused = true)]
async fn the_task_ends_when_the_service_stops() {
    let source = Arc::new(FakeEndpointWatch::new());
    let running = Running::start(&source, vec![target()]);
    Running::settle().await;

    running.stop().await;
}

/// A source whose calls never answer; with `lists`, its lists answer an empty listing and only
/// its watches never answer.
#[derive(Debug)]
struct SilentSource {
    lists: bool,
}

#[async_trait::async_trait]
impl EndpointWatch for SilentSource {
    async fn list(&self, _target: &WatchTarget) -> Result<EndpointListing, EndpointWatchError> {
        if self.lists {
            return Ok(EndpointListing {
                resource_version: "1".to_owned(),
                slices: Vec::new(),
            });
        }
        std::future::pending().await
    }

    async fn watch(
        &self,
        _target: &WatchTarget,
        _resource_version: &str,
    ) -> Result<WatchBatch, EndpointWatchError> {
        std::future::pending().await
    }
}

#[tokio::test(start_paused = true)]
async fn a_stop_while_a_list_waits_for_its_answer_ends_the_task() {
    let running = Running::start_with(Arc::new(SilentSource { lists: false }), vec![target()]);
    tokio::time::sleep(Duration::from_millis(10)).await;

    running.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_stop_while_a_watch_waits_for_its_answer_ends_the_task() {
    let running = Running::start_with(Arc::new(SilentSource { lists: true }), vec![target()]);
    tokio::time::sleep(Duration::from_millis(10)).await;

    running.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_list_that_outlasts_its_timeout_is_retried_until_the_stop() {
    let running = Running::start_with(Arc::new(SilentSource { lists: false }), vec![target()]);
    tokio::time::sleep(Duration::from_millis(2_500)).await;

    assert_eq!(running.addresses().len(), 0);
    running.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_stop_during_the_pause_after_a_failed_list_ends_the_task_before_a_watch() {
    let source = Arc::new(FakeEndpointWatch::new());
    source.fail_next(u32::MAX);
    let running = Running::start(&source, vec![target()]);
    tokio::time::sleep(Duration::from_millis(10)).await;

    running.stop().await;
    assert_eq!(source.list_calls().len(), 1);
    assert_eq!(source.watch_calls().len(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_watcher_without_targets_ends_at_once() {
    let source = Arc::new(FakeEndpointWatch::new());
    let running = Running::start(&source, Vec::new());

    running.task.await.unwrap();
}

#[test]
fn the_default_settings_hold_a_watch_longer_than_the_source_does() {
    let settings = WatcherSettings::default();

    assert!(settings.watch_timeout > Duration::from_secs(300));
    assert_eq!(EndpointWatcher::name(), "endpoint-watcher");
}
