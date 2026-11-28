//! The long poll with which a gateway pod reports the policy version it enforces (FR-76,
//! Story 13.3).
//!
//! The Sync-Fence coordinator of `iam-control` asks every pod `atLeast=V&offset=O&wait=T` and
//! returns a write only when each pod answered. A pod answers when
//!
//! - it has published version `V` or a later one and the re-evaluation of its open streams
//!   (Story 11.2) has finished for `V`, so no stream still decides on older state; or
//! - its bootstrap captured an end of the state topic beyond the offset `O` of the write, because
//!   the state that bootstrap publishes then necessarily contains the write.
//!
//! Otherwise the poll waits for either, at most `T` capped at `FRESHNESS_HARD_BOUND` plus one
//! second, and ends [`AppliedAnswer::Unanswered`]. At most
//! [`AppliedPollSettings::max_concurrent`] polls wait at once; a further one is
//! [`AppliedAnswer::Busy`] at once. Every waiting poll subscribes to the one channel of the
//! [`PolicyVersionBoard`], so a pod holds a single watch on the published version however many
//! polls wait.

mod high_water;
mod query;

use std::future::pending;
use std::sync::Arc;
use std::time::Duration;

use iam_domain::PolicyVersion;
use tokio::sync::Semaphore;

pub use high_water::{BootstrapHighWater, RecordingBootstrapLog};
pub use query::AppliedQuery;

use super::stream_reauthorizer::ReevaluationBoard;
use crate::read_your_writes::PolicyVersionBoard;

/// How much longer than the hard bound a poll may wait.
const WAIT_MARGIN: Duration = Duration::from_secs(1);

/// What the pod reports about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedPollSettings {
    /// The name of the pod, or `unknown` when the downward API provides none.
    pub pod: String,
    /// The configured `FRESHNESS_HARD_BOUND`, reported as `hardBoundMs` and bounding every wait.
    pub hard_bound: Duration,
    /// `APPLIED_POLL_MAX_CONCURRENT`: how many polls may wait at once.
    pub max_concurrent: usize,
}

/// What a poll came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppliedAnswer {
    /// The pod enforces the version; `published` is the version it has published, when it has
    /// published one.
    Applied {
        /// The version published now.
        published: Option<PolicyVersion>,
    },
    /// The wait ended without the pod reaching the version.
    Unanswered,
    /// `APPLIED_POLL_MAX_CONCURRENT` polls wait already.
    Busy,
}

/// The pod's answer to the Sync-Fence coordinator.
#[derive(Debug)]
pub struct AppliedPoll {
    versions: Arc<PolicyVersionBoard>,
    reevaluation: Arc<ReevaluationBoard>,
    high_water: Arc<BootstrapHighWater>,
    settings: AppliedPollSettings,
    slots: Semaphore,
}

impl AppliedPoll {
    /// A poll over the published version, the finished re-evaluations and the captured `HW0` of
    /// the pod.
    #[must_use]
    pub fn new(
        versions: Arc<PolicyVersionBoard>,
        reevaluation: Arc<ReevaluationBoard>,
        high_water: Arc<BootstrapHighWater>,
        settings: AppliedPollSettings,
    ) -> Self {
        let slots = Semaphore::new(settings.max_concurrent);
        Self {
            versions,
            reevaluation,
            high_water,
            settings,
            slots,
        }
    }

    /// The name of the pod.
    #[must_use]
    pub fn pod(&self) -> &str {
        &self.settings.pod
    }

    /// The configured `FRESHNESS_HARD_BOUND`.
    #[must_use]
    pub const fn hard_bound(&self) -> Duration {
        self.settings.hard_bound
    }

    /// Answers for `at_least` at once when the pod enforces it, and otherwise waits for it up to
    /// `wait`, capped at the hard bound plus one second.
    pub async fn poll(
        &self,
        at_least: PolicyVersion,
        offset: i64,
        wait: Duration,
    ) -> AppliedAnswer {
        if self.enforces(at_least, offset) {
            return self.applied();
        }
        let Ok(_slot) = self.slots.try_acquire() else {
            return AppliedAnswer::Busy;
        };
        let wait = wait.min(self.settings.hard_bound.saturating_add(WAIT_MARGIN));
        match tokio::time::timeout(wait, self.until_enforced(at_least, offset)).await {
            Ok(()) => self.applied(),
            Err(_elapsed) => AppliedAnswer::Unanswered,
        }
    }

    fn applied(&self) -> AppliedAnswer {
        AppliedAnswer::Applied {
            published: self.versions.published(),
        }
    }

    /// Whether the pod enforces `at_least` now.
    fn enforces(&self, at_least: PolicyVersion, offset: i64) -> bool {
        self.high_water.covers(offset) || self.settled(at_least)
    }

    /// Whether `at_least` is published and no stream is left undecided against it.
    fn settled(&self, at_least: PolicyVersion) -> bool {
        self.versions
            .published()
            .is_some_and(|published| published >= at_least)
            && self.reevaluation.finished() >= at_least.value()
    }

    async fn until_enforced(&self, at_least: PolicyVersion, offset: i64) {
        tokio::select! {
            () = self.high_water.covered(offset) => {}
            () = self.settled_at(at_least) => {}
        }
    }

    /// Completes once `at_least` is published and its re-evaluation has finished.
    async fn settled_at(&self, at_least: PolicyVersion) {
        let live = self.versions.published_at_least(at_least).await;
        let done = self.reevaluation.reached(at_least);
        // A board that is gone can never publish the version, so its poll never settles.
        if live { done.await } else { pending().await }
    }
}

#[cfg(test)]
mod tests;
