//! The `OutboxRelay` singleton that publishes the outbox to Kafka (FR-46, FR-47, NFR-26).
//!
//! It publishes every row in `(policy_version, seq)` order inside a batch fenced by the advisory
//! lock, and deletes what it published a week ago.
//!
//! One relay leads the fleet. A replica that starts to lead takes the relay over: it increments
//! `iam_policy_epoch.relay_epoch`, publishes the latest state of every key again under the new
//! epoch and only then continues with the unpublished rows.
//!
//! Every record carries the epoch in its `iam-relay-epoch` header, and the marks of a leader that
//! was replaced are refused, so a zombie relay's late batch can neither win a key nor mark a row.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use iam_domain::{
    KafkaTopicInspector, LeaderBatch, OutboxRow, OutboxStore, PolicyLogError, PolicyLogProducer,
    PolicyLogRecord, PublishedRow, RelayEpoch, SingletonLeadership, SingletonTask,
};
use shared_domain::{BoxError, Clock};
use tokio::sync::{Notify, watch};

use crate::singleton_loop::{SingletonInterval, SingletonLoop, SingletonWork};

/// How long a published row stays in the outbox.
pub const PUBLISHED_RETENTION: Duration = Duration::from_hours(168);

/// How often a leader that found nothing to do asks the database again.
pub const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The settings of the relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboxRelaySettings {
    /// The most rows that one batch publishes; at least 1.
    pub batch_size: u32,
    /// How long a published row stays in the outbox before the cleanup deletes it.
    pub retention: Duration,
    /// How often the cleanup runs.
    pub cleanup_every: Duration,
    /// How long a verdict on the topic configuration is trusted before the cluster is asked again.
    pub verdict_ttl: Duration,
}

impl Default for OutboxRelaySettings {
    /// 500 rows per batch, a week of retention, a cleanup and a configuration check every minute
    /// and every 5 seconds.
    fn default() -> Self {
        Self {
            batch_size: 500,
            retention: PUBLISHED_RETENTION,
            cleanup_every: Duration::from_mins(1),
            verdict_ttl: Duration::from_secs(5),
        }
    }
}

/// The ports the relay works through.
#[derive(Debug, Clone)]
pub struct OutboxRelayPorts {
    /// The outbox that is drained.
    pub store: Arc<dyn OutboxStore>,
    /// The producer that appends the records to Kafka.
    pub producer: Arc<dyn PolicyLogProducer>,
    /// The check of the configuration of the topics, consulted before anything is published.
    pub inspector: Arc<dyn KafkaTopicInspector>,
}

/// A producer acknowledged fewer records than it was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the producer acknowledged {acknowledged} of {sent} records")]
pub struct IncompleteAcknowledgement {
    /// The number of records that were sent.
    pub sent: usize,
    /// The number of offsets that came back.
    pub acknowledged: usize,
}

/// When the configuration of the topics was last judged, and how.
#[derive(Debug, Clone, Copy)]
struct Judgement {
    at: SystemTime,
    allowed: bool,
}

/// The relay task: dispatches one fenced batch per poll.
#[derive(Debug)]
pub struct OutboxRelay {
    ports: OutboxRelayPorts,
    clock: Arc<dyn Clock>,
    settings: OutboxRelaySettings,
    held: Mutex<Option<RelayEpoch>>,
    judged: Mutex<Option<Judgement>>,
    cleaned: Mutex<Option<SystemTime>>,
    leading: Arc<watch::Sender<bool>>,
}

fn log_misconfiguration(violations: &str) {
    tracing::error!(
        violations,
        "the Kafka topics are misconfigured: nothing is published"
    );
}

fn log_takeover(epoch: RelayEpoch) {
    tracing::info!(epoch = epoch.value(), "the relay took over");
}

fn log_deleted(deleted: u64) {
    tracing::debug!(deleted, "published outbox rows deleted");
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl OutboxRelay {
    /// The task: its name in the log and in `iam_task_state`, and the constant that the advisory
    /// lock of its batches is taken on.
    pub const TASK: SingletonTask = SingletonTask::new("outbox-relay", 7_004);

    /// A relay over `ports`. `leading` tells the listener of the wake-up whether this replica
    /// leads: `true` while it leads the batches, `false` once another replica does.
    #[must_use]
    pub fn new(
        ports: OutboxRelayPorts,
        clock: Arc<dyn Clock>,
        settings: OutboxRelaySettings,
        leading: Arc<watch::Sender<bool>>,
    ) -> Self {
        Self {
            ports,
            clock,
            settings,
            held: Mutex::new(None),
            judged: Mutex::new(None),
            cleaned: Mutex::new(None),
            leading,
        }
    }

    /// The loop that runs the task: a batch every [`POLL_INTERVAL`], or as soon as `wake` is
    /// notified.
    #[must_use]
    pub fn into_loop(
        self,
        leadership: Arc<dyn SingletonLeadership>,
        clock: Arc<dyn Clock>,
        wake: Arc<Notify>,
    ) -> SingletonLoop {
        let poll = SingletonInterval::clamped(POLL_INTERVAL);
        SingletonLoop::new(Self::TASK, poll, leadership, clock, Arc::new(self)).with_wake(wake)
    }

    /// Whether the configuration of the topics allows publishing now; the cluster is asked at most
    /// once per `verdict_ttl`.
    async fn configuration_allows(&self) -> Result<bool, BoxError> {
        let now = self.clock.now();
        match self.recent_judgement(now) {
            Some(allowed) => Ok(allowed),
            None => self.judge(now).await,
        }
    }

    /// The last judgement, while it is younger than `verdict_ttl`.
    fn recent_judgement(&self, now: SystemTime) -> Option<bool> {
        let judgement = (*locked(&self.judged))?;
        let age = now.duration_since(judgement.at).ok()?;
        (age < self.settings.verdict_ttl).then_some(judgement.allowed)
    }

    /// Asks the cluster and remembers the answer.
    async fn judge(&self, now: SystemTime) -> Result<bool, BoxError> {
        let verdict = self.ports.inspector.inspect().await?;
        let allowed = verdict.passed();
        if !allowed {
            log_misconfiguration(&verdict.describe());
        }
        *locked(&self.judged) = Some(Judgement { at: now, allowed });
        Ok(allowed)
    }

    /// The epoch this replica publishes under; a replica that is not the latest leader takes the
    /// relay over first.
    async fn epoch(&self) -> Result<RelayEpoch, BoxError> {
        let current = self.ports.store.current_relay_epoch().await?;
        if self.holds(current) {
            Ok(current)
        } else {
            self.take_over().await
        }
    }

    fn holds(&self, epoch: RelayEpoch) -> bool {
        *locked(&self.held) == Some(epoch)
    }

    /// Increments the relay epoch and publishes the latest state of every key under it.
    async fn take_over(&self) -> Result<RelayEpoch, BoxError> {
        let takeover = self.ports.store.take_over_relay().await?;
        self.publish_in_chunks(&takeover.republish, takeover.epoch)
            .await?;
        *locked(&self.held) = Some(takeover.epoch);
        log_takeover(takeover.epoch);
        Ok(takeover.epoch)
    }

    async fn publish_in_chunks(
        &self,
        rows: &[OutboxRow],
        epoch: RelayEpoch,
    ) -> Result<(), BoxError> {
        let size = usize::try_from(self.settings.batch_size)
            .unwrap_or(usize::MAX)
            .max(1);
        for chunk in rows.chunks(size) {
            self.publish(chunk, epoch).await?;
        }
        Ok(())
    }

    /// Appends `rows` and marks them published once the producer acknowledged every one.
    async fn publish(&self, rows: &[OutboxRow], epoch: RelayEpoch) -> Result<(), BoxError> {
        if rows.is_empty() {
            return Ok(());
        }
        let records: Vec<PolicyLogRecord> = rows
            .iter()
            .map(|row| PolicyLogRecord::of(row, epoch))
            .collect();
        let offsets = self
            .ports
            .producer
            .publish(&records)
            .await
            .inspect_err(|error| self.forget_epoch_when_fenced(error))?;
        if offsets.len() != rows.len() {
            return Err(Box::new(IncompleteAcknowledgement {
                sent: rows.len(),
                acknowledged: offsets.len(),
            }));
        }
        let published: Vec<PublishedRow> = rows
            .iter()
            .zip(offsets)
            .map(|(row, offset)| PublishedRow { id: row.id, offset })
            .collect();
        self.ports
            .store
            .mark_published(&published, epoch, self.clock.now())
            .await?;
        Ok(())
    }

    /// A fenced producer means that a newer relay leads: the next batch takes the relay over again.
    fn forget_epoch_when_fenced(&self, error: &PolicyLogError) {
        if matches!(error, PolicyLogError::Fenced(_)) {
            *locked(&self.held) = None;
        }
    }

    /// Deletes the rows published before the retention, at most once per `cleanup_every`.
    async fn clean(&self) -> Result<(), BoxError> {
        let now = self.clock.now();
        if self.cleaned_recently(now) {
            return Ok(());
        }
        if let Some(before) = now.checked_sub(self.settings.retention) {
            let deleted = self.ports.store.delete_published_before(before).await?;
            log_deleted(deleted);
        }
        *locked(&self.cleaned) = Some(now);
        Ok(())
    }

    fn cleaned_recently(&self, now: SystemTime) -> bool {
        let last = *locked(&self.cleaned);
        last.and_then(|last| now.duration_since(last).ok())
            .is_some_and(|age| age < self.settings.cleanup_every)
    }
}

#[async_trait::async_trait]
impl SingletonWork for OutboxRelay {
    async fn run(&self, _batch: &mut dyn LeaderBatch) -> Result<(), BoxError> {
        self.leading.send_replace(true);
        if !self.configuration_allows().await? {
            return Ok(());
        }
        let epoch = self.epoch().await?;
        let rows = self
            .ports
            .store
            .claim_unpublished(self.settings.batch_size)
            .await?;
        self.publish(&rows, epoch).await?;
        self.clean().await
    }

    async fn on_follower(&self) {
        self.leading.send_replace(false);
    }
}

#[cfg(test)]
mod tests;
