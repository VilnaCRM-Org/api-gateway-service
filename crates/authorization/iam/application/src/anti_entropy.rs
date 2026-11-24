//! The `AntiEntropyChecker` singleton: compares the state topic with PostgreSQL and repairs a lost
//! record (FR-77).
//!
//! Every `ANTI_ENTROPY_HEAD_INTERVAL` the head check compares the newest `__head` of the topic with
//! PostgreSQL, verifies that the offsets the relay stored for its recent rows still hold the
//! expected versions, and compares the last record by offset of every key written since the
//! previous check with the newest PostgreSQL version of the key. A record that is lost or lower is
//! repaired by clearing `published_at` of its outbox row, so the relay sends it again well inside
//! `min.compaction.lag.ms`, before compaction could keep a stale value of a zombie relay.
//!
//! Every `ANTI_ENTROPY_FULL_INTERVAL` the shadow bootstrap rebuilds the state from the whole topic
//! and compares its digest with the head of the topic and with PostgreSQL. What the task cannot
//! repair (a digest mismatch, a loss older than the outbox retention, a topic ahead of PostgreSQL)
//! is an alert: an error log, the `anti_entropy_repairs_total` counter, and the call for the
//! runbook (the resync of Story 7.10, or the topic-ahead runbook).
//!
//! The hold on the relay is shared state, not memory of one replica: every committed batch writes
//! whether the topic is ahead to `iam_task_state`, in the transaction of the batch, and the relay
//! of any replica reads it in its own leader batch (see [`crate::OutboxRelay`]).

mod alert;
mod full;
mod head;
mod hold;
mod settings;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use iam_domain::{
    AntiEntropyStore, LeaderBatch, PolicyDigest, PolicyLogTail, PolicyLogTailError,
    SingletonLeadership, SingletonTask, StateRecordCodec, TailRecord, TaskStateRepository,
};
use shared_domain::{BoxError, Clock};

use full::FullCheck;
use head::HeadCheck;

pub use alert::{AntiEntropyAlert, RESYNC_RUNBOOK, TOPIC_AHEAD_RUNBOOK};
pub use hold::{AntiEntropyCounters, TopicAheadHold};
pub use settings::{AntiEntropySettings, InvalidAntiEntropySettings};

use crate::singleton_loop::{
    MAX_SINGLETON_INTERVAL, SingletonInterval, SingletonLoop, SingletonWork,
};

/// How far back the head check looks for recent records when no check ran before.
pub(crate) const RECENT_WINDOW: Duration = Duration::from_mins(30);

/// How much earlier than the previous check the written keys are read, so that a row that was
/// written before that check and committed after it is still found.
pub(crate) const OVERLAP: Duration = Duration::from_mins(1);

/// The ports the task works through.
#[derive(Debug, Clone)]
pub struct AntiEntropyPorts {
    /// What PostgreSQL holds, and the repair of a lost record.
    pub store: Arc<dyn AntiEntropyStore>,
    /// The bounded reads of the state topic.
    pub tail: Arc<dyn PolicyLogTail>,
    /// The state that the committed batches left, which holds the time of the previous check.
    pub task_states: Arc<dyn TaskStateRepository>,
    /// Reads the head of a version.
    pub codec: Arc<dyn StateRecordCodec>,
    /// Hashes the entities of the shadow bootstrap.
    pub digest: Arc<dyn PolicyDigest>,
}

/// The anti-entropy task: a head check per interval and a shadow bootstrap per full interval.
#[derive(Debug)]
pub struct AntiEntropyChecker {
    ports: AntiEntropyPorts,
    clock: Arc<dyn Clock>,
    settings: AntiEntropySettings,
    counters: Arc<AntiEntropyCounters>,
    hold: Arc<TopicAheadHold>,
    last_full: Mutex<Option<SystemTime>>,
    healthy: AtomicBool,
}

impl AntiEntropyChecker {
    /// The task: its name in the log and in `iam_task_state`, and the constant that the advisory
    /// lock of its batches is taken on.
    pub const TASK: SingletonTask = SingletonTask::new("anti-entropy", 7_007);

    /// The task over `ports`; the repairs and the alerts are counted in `counters`, and a topic
    /// that is ahead of PostgreSQL sets `hold`, which the relay honours.
    #[must_use]
    pub fn new(
        ports: AntiEntropyPorts,
        clock: Arc<dyn Clock>,
        settings: AntiEntropySettings,
        counters: Arc<AntiEntropyCounters>,
        hold: Arc<TopicAheadHold>,
    ) -> Self {
        Self {
            ports,
            clock,
            settings,
            counters,
            hold,
            last_full: Mutex::new(None),
            healthy: AtomicBool::new(false),
        }
    }

    /// The loop that runs the task. It polls at `ANTI_ENTROPY_HEAD_INTERVAL`, or at the longest
    /// retry interval of a singleton when that is shorter; a poll that finds the last committed
    /// check younger than the head interval ends without running anything.
    #[must_use]
    pub fn into_loop(
        self,
        leadership: Arc<dyn SingletonLeadership>,
        clock: Arc<dyn Clock>,
    ) -> SingletonLoop {
        let poll =
            SingletonInterval::clamped(self.settings.head_interval().min(MAX_SINGLETON_INTERVAL));
        SingletonLoop::new(Self::TASK, poll, leadership, clock, Arc::new(self))
    }

    /// Whether the last shadow bootstrap of this replica found the topic and PostgreSQL in step.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::SeqCst)
    }

    /// Counts the alert, marks the state not healthy and tells the operator which runbook to open.
    fn raise(&self, alert: &AntiEntropyAlert) {
        self.healthy.store(false, Ordering::SeqCst);
        self.counters.record();
        let runbook = alert.runbook();
        tracing::error!(
            alert = %alert,
            runbook,
            metric = "anti_entropy_repairs_total",
            "anti-entropy alert: follow the runbook in docs/operations.md"
        );
    }

    /// The failure of a read of the topic; a record that cannot be read is also an alert.
    fn tail_failure(&self, error: PolicyLogTailError) -> BoxError {
        if let PolicyLogTailError::Malformed { offset } = &error {
            self.raise(&AntiEntropyAlert::UnreadableRecord {
                offset: *offset,
                reason: error.to_string(),
            });
        }
        Box::new(error)
    }

    /// The records of `from <= offset < up_to`.
    async fn read(&self, from: i64, up_to: i64) -> Result<Vec<TailRecord>, BoxError> {
        self.ports
            .tail
            .read_range(from, up_to)
            .await
            .map_err(|error| self.tail_failure(error))
    }

    /// The time from which the head check reads the rows that were written, and whether a previous
    /// check was recorded.
    async fn last_check(&self) -> Result<Option<SystemTime>, BoxError> {
        let state = self.ports.task_states.find(Self::TASK.name()).await?;
        Ok(state.map(|state| state.last_run_at))
    }

    fn full_due(&self, now: SystemTime) -> bool {
        let last = *self
            .last_full
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        last.is_none_or(|last| {
            now.duration_since(last)
                .is_ok_and(|elapsed| elapsed >= self.settings.full_interval())
        })
    }

    /// One batch: the head check, and the full check when it is due. The hold that the checks leave
    /// is written to the shared state in the batch, so that the relay of any replica reads it, and
    /// the batch counts as a completed check only when it commits.
    async fn check(&self, batch: &mut dyn LeaderBatch) -> Result<(), BoxError> {
        let now = self.clock.now();
        let previous = self.last_check().await?;
        let since = previous
            .and_then(|at| at.checked_sub(OVERLAP))
            .or_else(|| now.checked_sub(RECENT_WINDOW))
            .unwrap_or(now);
        HeadCheck(self).check_head(now, since).await?;
        if self.full_due(now) {
            FullCheck(self).check_full().await?;
            self.remember_full(now);
        }
        batch.write_topic_ahead(self.hold.is_set(), now).await?;
        Ok(())
    }

    /// Whether a head check is due at `now`.
    async fn due(&self, now: SystemTime) -> Result<bool, BoxError> {
        let last = self.last_check().await?;
        Ok(last.is_none_or(|at| {
            now.duration_since(at)
                .is_ok_and(|elapsed| elapsed >= self.settings.head_interval())
        }))
    }

    /// Closes the reader of the state topic: the task stopped, or another replica leads it.
    async fn release_tail(&self) {
        self.ports.tail.close().await;
    }

    fn remember_full(&self, now: SystemTime) {
        *self
            .last_full
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(now);
    }
}

#[async_trait::async_trait]
impl SingletonWork for AntiEntropyChecker {
    async fn run(&self, batch: &mut dyn LeaderBatch) -> Result<(), BoxError> {
        self.check(batch).await
    }

    async fn is_due(&self, now: SystemTime) -> Result<bool, BoxError> {
        self.due(now).await
    }

    async fn on_follower(&self) {
        self.release_tail().await;
    }

    async fn on_stop(&self) {
        self.release_tail().await;
    }

    fn interruptible(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests;
