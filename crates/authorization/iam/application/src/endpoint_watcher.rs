//! The `EndpointWatcher` task: keeps the zone-annotated endpoint set of every watched Service
//! current (FR-87).
//!
//! Each target runs the same loop: list the slices, publish them, then follow the changes from
//! the last resource version. A dropped connection or a failing source resumes from the same
//! version after a pause; an expired version (HTTP 410) lists again. The loop never gives up
//! while the service runs, and a failing source keeps the last known endpoints.

use std::sync::Arc;
use std::time::Duration;

use iam_domain::{EndpointWatch, EndpointWatchError, WatchBatch, WatchTarget};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::endpoint_directory::EndpointDirectory;

/// The pauses and limits of the watcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatcherSettings {
    /// The pause after a watch call that ended without an event.
    pub idle_pause: Duration,
    /// The pause after a failed call, before it retries.
    pub retry_pause: Duration,
    /// The longest a `list` call may take.
    pub list_timeout: Duration,
    /// The longest a `watch` call may take: longer than the time the source holds a watch open.
    pub watch_timeout: Duration,
}

impl Default for WatcherSettings {
    fn default() -> Self {
        Self {
            idle_pause: Duration::from_secs(1),
            retry_pause: Duration::from_secs(1),
            list_timeout: Duration::from_secs(10),
            watch_timeout: Duration::from_secs(330),
        }
    }
}

/// How following the changes of a target ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Followed {
    /// The service is stopping.
    Stopped,
    /// The resource version expired: list again.
    Relist,
}

/// The per-replica task that watches the endpoints of the targets.
#[derive(Debug)]
pub struct EndpointWatcher {
    source: Arc<dyn EndpointWatch>,
    directory: Arc<EndpointDirectory>,
    targets: Vec<WatchTarget>,
    settings: WatcherSettings,
}

impl EndpointWatcher {
    /// A watcher of `targets` that publishes into `directory`.
    #[must_use]
    pub fn new(
        source: Arc<dyn EndpointWatch>,
        directory: Arc<EndpointDirectory>,
        targets: Vec<WatchTarget>,
        settings: WatcherSettings,
    ) -> Self {
        Self {
            source,
            directory,
            targets,
            settings,
        }
    }

    /// The name of the task, for the log entries of the supervisor.
    #[must_use]
    pub const fn name() -> &'static str {
        "endpoint-watcher"
    }

    /// Watches every target until the stop flag is set or its sender is gone.
    pub async fn run(self, shutdown: watch::Receiver<bool>) {
        let watcher = Arc::new(self);
        let mut trackers = JoinSet::new();
        for target in watcher.targets.clone() {
            let watcher = Arc::clone(&watcher);
            let shutdown = shutdown.clone();
            trackers.spawn(async move { watcher.track(target, shutdown).await });
        }
        while trackers.join_next().await.is_some() {}
    }

    async fn track(&self, target: WatchTarget, mut shutdown: watch::Receiver<bool>) {
        while !*shutdown.borrow() {
            let Some(version) = self.relist(&target, &mut shutdown).await else {
                return;
            };
            if self.follow(&target, version, &mut shutdown).await == Followed::Stopped {
                return;
            }
        }
    }

    /// Lists and publishes the slices of `target`, retrying until it succeeds; `None` when the
    /// service is stopping.
    async fn relist(
        &self,
        target: &WatchTarget,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Option<String> {
        loop {
            let call = self.source.list(target);
            match bounded(self.settings.list_timeout, shutdown, call).await? {
                Ok(listing) => {
                    self.directory.replace(target, listing.slices);
                    return Some(listing.resource_version);
                }
                Err(error) => log_failure(target, "list", &error),
            }
            if !pause(self.settings.retry_pause, shutdown).await {
                return None;
            }
        }
    }

    /// Applies the changes of `target` after `version` until the version expires or the service
    /// stops.
    async fn follow(
        &self,
        target: &WatchTarget,
        mut version: String,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Followed {
        loop {
            let call = self.source.watch(target, &version);
            let pause_for = match bounded(self.settings.watch_timeout, shutdown, call).await {
                None => return Followed::Stopped,
                Some(Ok(batch)) => self.publish(target, batch, &mut version),
                Some(Err(EndpointWatchError::Expired)) => return Followed::Relist,
                Some(Err(error)) => {
                    log_failure(target, "watch", &error);
                    self.settings.retry_pause
                }
            };
            if !pause_for.is_zero() && !pause(pause_for, shutdown).await {
                return Followed::Stopped;
            }
        }
    }

    /// Applies a batch and returns the pause before the next call: none after news, the idle
    /// pause after an empty batch.
    fn publish(&self, target: &WatchTarget, batch: WatchBatch, version: &mut String) -> Duration {
        let idle = batch.changes.is_empty();
        for change in batch.changes {
            self.directory.apply(target, change);
        }
        *version = batch.resource_version;
        if idle {
            self.settings.idle_pause
        } else {
            Duration::ZERO
        }
    }
}

/// Runs `call` for at most `limit`; a timeout is a failure of the source. `None` when the service
/// is stopping first.
async fn bounded<T>(
    limit: Duration,
    shutdown: &mut watch::Receiver<bool>,
    call: impl Future<Output = Result<T, EndpointWatchError>>,
) -> Option<Result<T, EndpointWatchError>> {
    tokio::select! {
        outcome = tokio::time::timeout(limit, call) => Some(outcome.unwrap_or_else(|_elapsed| {
            Err(EndpointWatchError::Unavailable("the call timed out".into()))
        })),
        stopping = shutdown.wait_for(|stopping| *stopping) => {
            drop(stopping);
            None
        }
    }
}

/// Waits for `duration`; `false` when the service is stopping instead.
async fn pause(duration: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(duration) => true,
        stopping = shutdown.wait_for(|stopping| *stopping) => {
            drop(stopping);
            false
        }
    }
}

fn log_failure(target: &WatchTarget, call: &str, error: &EndpointWatchError) {
    tracing::warn!(
        target_service = %target,
        call,
        error = %error,
        "endpoint discovery call failed; the last known endpoints stay in force"
    );
}

#[cfg(test)]
mod tests;
