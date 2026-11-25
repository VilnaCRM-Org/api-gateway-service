//! The read-your-writes barrier of the gateway (FR-14, Story 10.10).
//!
//! A caller that names a policy version `V` is never decided on a snapshot older than `V`. The
//! barrier compares `V` with the highest version the pod has seen in the log: a `V` above it is
//! refused at once, because no task may wait for a version that may never arrive; otherwise the
//! request waits on a watch channel, up to the configured wait, for a snapshot of `V` or higher.
//! Without a version the barrier costs nothing, and the caller does not call it.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use iam_domain::{PolicyVersion, PolicyView};
use tokio::sync::watch;

/// The `published` value while no snapshot is published.
const NOTHING_PUBLISHED: i64 = -1;

/// What the pod knows about policy versions: the highest one seen in the log and the one
/// published last.
///
/// The apply thread feeds it; the barrier reads it. Reading the highest version seen is one atomic
/// load.
#[derive(Debug)]
pub struct PolicyVersionBoard {
    highest_seen: AtomicI64,
    published: watch::Sender<i64>,
}

impl Default for PolicyVersionBoard {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyVersionBoard {
    /// A board of a pod that has seen and published nothing.
    #[must_use]
    pub fn new() -> Self {
        Self {
            highest_seen: AtomicI64::new(NOTHING_PUBLISHED),
            published: watch::Sender::new(NOTHING_PUBLISHED),
        }
    }

    /// Records that the log held `version`; the highest seen never goes down.
    pub fn note_seen(&self, version: PolicyVersion) {
        self.highest_seen
            .fetch_max(version.value(), Ordering::AcqRel);
    }

    /// Records the version now published, or that none is: waiters of a version at or below it
    /// wake up. A published version is a seen one.
    pub fn note_published(&self, version: Option<PolicyVersion>) {
        let value = version.map_or(NOTHING_PUBLISHED, PolicyVersion::value);
        if version.is_some() {
            self.highest_seen.fetch_max(value, Ordering::AcqRel);
        }
        self.published.send_if_modified(|held| {
            let changed = *held != value;
            *held = value;
            changed
        });
    }

    /// The highest version seen in the log, or `None` before any.
    #[must_use]
    pub fn highest_seen(&self) -> Option<PolicyVersion> {
        PolicyVersion::new(self.highest_seen.load(Ordering::Acquire)).ok()
    }

    /// Whether `minimum` has been seen in the log.
    fn has_seen(&self, minimum: PolicyVersion) -> bool {
        self.highest_seen.load(Ordering::Acquire) >= minimum.value()
    }

    /// Resolves once a snapshot of `minimum` or higher is published; never when the board is
    /// dropped first.
    async fn published_at_least(&self, minimum: PolicyVersion) -> bool {
        let mut receiver = self.published.subscribe();
        receiver
            .wait_for(|published| *published >= minimum.value())
            .await
            .is_ok()
    }
}

/// What the barrier decided for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarrierVerdict {
    /// A snapshot of the wanted version or higher is published: go on.
    Proceed,
    /// The version is not there yet, or never arrives: 503 `iam_propagating`.
    Propagating,
}

/// The barrier over the published snapshot and the board of versions.
#[derive(Debug, Clone)]
pub struct ReadYourWritesBarrier {
    view: Arc<dyn PolicyView>,
    board: Arc<PolicyVersionBoard>,
    max_wait: Duration,
}

impl ReadYourWritesBarrier {
    /// A barrier that waits at most `max_wait` (`RYW_MAX_WAIT`) for a snapshot to be published.
    #[must_use]
    pub const fn new(
        view: Arc<dyn PolicyView>,
        board: Arc<PolicyVersionBoard>,
        max_wait: Duration,
    ) -> Self {
        Self {
            view,
            board,
            max_wait,
        }
    }

    /// Lets a request through when a snapshot of `minimum` or higher is published, waits for one
    /// when the log holds `minimum` already, and refuses otherwise.
    pub async fn admit(&self, minimum: PolicyVersion) -> BarrierVerdict {
        if !self.board.has_seen(minimum) {
            return BarrierVerdict::Propagating;
        }
        if self.published(minimum) {
            return BarrierVerdict::Proceed;
        }
        match tokio::time::timeout(self.max_wait, self.board.published_at_least(minimum)).await {
            Ok(true) => BarrierVerdict::Proceed,
            Ok(false) | Err(_) => BarrierVerdict::Propagating,
        }
    }

    fn published(&self, minimum: PolicyVersion) -> bool {
        self.view
            .current()
            .is_some_and(|snapshot| snapshot.version() >= minimum)
    }
}

#[cfg(test)]
mod tests;
