//! `KrafkaPolicyLogTail`: bounded reads of the state topic with krafka (FR-77).
//!
//! The reader is a consumer without a group that assigns partition 0 by hand and reads
//! `read_committed`, so a record of a transaction that did not commit is never seen. It never
//! commits an offset. Every read seeks to its own start, polls until the end of the range or the
//! request timeout, and returns at most [`TAIL_READ_LIMIT`] records. Story 9.3 adds the bootstrap
//! principal, the tail mode and the reseek of the gateway.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use iam_domain::{
    PolicyLogTail, PolicyLogTailError, PolicyVersion, RelayEpoch, STATE_PARTITION, TAIL_READ_LIMIT,
    TailRecord,
};
use krafka::KrafkaError;
use krafka::consumer::{AutoOffsetReset, Consumer, ConsumerRecord, IsolationLevel};
use shared_domain::BoxError;

use super::krafka_cluster::{authenticated, builder};
use super::settings::KafkaSettings;

/// How long one poll waits for records.
const POLL_TIMEOUT: Duration = Duration::from_millis(200);

/// The reads did not reach the end of the range before the request timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the state topic did not deliver the range before the request timeout")]
struct ReadTimedOut;

/// Reads the state topic through one lazily opened consumer.
///
/// A failed read drops the consumer, so the next read opens a new one.
pub struct KrafkaPolicyLogTail {
    settings: KafkaSettings,
    consumer: Mutex<Option<Arc<Consumer>>>,
}

impl std::fmt::Debug for KrafkaPolicyLogTail {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KrafkaPolicyLogTail")
            .field("topic", &self.settings.policy_topic)
            .finish_non_exhaustive()
    }
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl KrafkaPolicyLogTail {
    /// A reader of the state topic of `settings`; nothing is opened until the first read.
    #[must_use]
    pub const fn new(settings: KafkaSettings) -> Self {
        Self {
            settings,
            consumer: Mutex::new(None),
        }
    }

    async fn consumer(&self) -> Result<Arc<Consumer>, KrafkaError> {
        let open = locked(&self.consumer).clone();
        if let Some(consumer) = open {
            return Ok(consumer);
        }
        let consumer = Arc::new(open_consumer(&self.settings).await?);
        *locked(&self.consumer) = Some(Arc::clone(&consumer));
        Ok(consumer)
    }

    /// Takes the cached consumer, if any, and closes it, so it is never dropped open.
    async fn release(&self) {
        let open = locked(&self.consumer).take();
        if let Some(consumer) = open {
            report_close(consumer.close().await);
        }
    }

    async fn checked_watermark(&self) -> Result<i64, PolicyLogTailError> {
        let read = self.high_watermark().await;
        if read.is_err() {
            self.release().await;
        }
        read.map_err(unavailable)
    }

    async fn high_watermark(&self) -> Result<i64, BoxError> {
        let consumer = self.consumer().await?;
        let (_low, high) = consumer
            .fetch_watermarks(&self.settings.policy_topic, STATE_PARTITION)
            .await?;
        drop(consumer);
        Ok(high)
    }

    async fn range(&self, from: i64, up_to: i64) -> Result<Vec<TailRecord>, PolicyLogTailError> {
        let read = self.collect(from, up_to).await;
        if read.is_err() {
            self.release().await;
        }
        read
    }

    /// The records of `from..min(up_to, watermark)`, at most [`TAIL_READ_LIMIT`].
    async fn collect(&self, from: i64, up_to: i64) -> Result<Vec<TailRecord>, PolicyLogTailError> {
        let end = up_to.min(self.high_watermark().await.map_err(unavailable)?);
        if from >= end {
            return Ok(Vec::new());
        }
        let consumer = self.consumer().await.map_err(into_unavailable)?;
        consumer
            .seek(&self.settings.policy_topic, STATE_PARTITION, from)
            .await
            .map_err(into_unavailable)?;
        let mut records = Vec::new();
        let mut done = false;
        let mut polls = polls_within(self.settings.request_timeout);
        while !done && polls > 0 {
            polls = polls.saturating_sub(1);
            let polled = consumer
                .poll(POLL_TIMEOUT)
                .await
                .map_err(into_unavailable)?;
            take_range(&mut records, polled, from, end)?;
            let position = consumer
                .position(&self.settings.policy_topic, STATE_PARTITION)
                .await;
            done = finished(records.len(), position, end);
        }
        drop(consumer);
        completed(records, done)
    }
}

/// Logs a consumer that did not close cleanly; it is closed either way.
fn report_close(closed: Result<(), KrafkaError>) {
    if let Err(error) = closed {
        log_unclosed(&error);
    }
}

fn log_unclosed(error: &KrafkaError) {
    tracing::warn!(%error, "the reader of the state topic did not close cleanly");
}

/// The records of a finished read, at most [`TAIL_READ_LIMIT`]; a read that did not finish within
/// the request timeout is unavailable.
fn completed(
    mut records: Vec<TailRecord>,
    done: bool,
) -> Result<Vec<TailRecord>, PolicyLogTailError> {
    if !done {
        return Err(unavailable(Box::new(ReadTimedOut)));
    }
    records.truncate(TAIL_READ_LIMIT);
    Ok(records)
}

/// How many polls fit into `timeout`: at least one.
fn polls_within(timeout: Duration) -> u128 {
    timeout
        .as_millis()
        .checked_div(POLL_TIMEOUT.as_millis())
        .map_or(1, |polls| polls.max(1))
}

/// Whether the read has what it was asked for: the limit, or a consumer that is past the range
/// (transaction markers and compacted offsets hold no record, so the position, not the last
/// record, tells that the end was reached).
fn finished(count: usize, position: Option<i64>, end: i64) -> bool {
    count >= TAIL_READ_LIMIT || position.is_some_and(|next| next >= end)
}

/// Adds the records of `polled` that lie in `from..end` to `records`.
fn take_range(
    records: &mut Vec<TailRecord>,
    polled: Vec<ConsumerRecord>,
    from: i64,
    end: i64,
) -> Result<(), PolicyLogTailError> {
    for record in polled {
        if record.offset >= from && record.offset < end {
            records.push(record_of(&record)?);
        }
    }
    Ok(())
}

async fn open_consumer(settings: &KafkaSettings) -> Result<Consumer, KrafkaError> {
    let kafka = builder(settings, authenticated(settings)).connect().await?;
    let consumer = kafka
        .consumer_without_group()
        .isolation_level(IsolationLevel::ReadCommitted)
        .auto_offset_reset(AutoOffsetReset::Earliest)
        .enable_auto_commit(false)
        .max_poll_records(i32::try_from(TAIL_READ_LIMIT).unwrap_or(i32::MAX))
        .build()
        .await?;
    consumer
        .assign(&settings.policy_topic, vec![STATE_PARTITION])
        .await?;
    Ok(consumer)
}

/// The tail record of a consumed record.
///
/// # Errors
///
/// [`PolicyLogTailError::Malformed`] when the record has no key or a key or value that is not
/// UTF-8, or lacks `iam-version` or `iam-relay-epoch` or carries a value that is not a
/// non-negative number.
pub(super) fn record_of(record: &ConsumerRecord) -> Result<TailRecord, PolicyLogTailError> {
    let malformed = || PolicyLogTailError::Malformed {
        offset: record.offset,
    };
    let key = record.key_str().ok_or_else(malformed)?.to_owned();
    let payload = match &record.value {
        Some(_) => Some(record.value_str().ok_or_else(malformed)?.to_owned()),
        None => None,
    };
    let number = |name: &str| -> Option<i64> { record.header_str(name)?.parse().ok() };
    let version = number("iam-version")
        .and_then(|value| PolicyVersion::new(value).ok())
        .ok_or_else(malformed)?;
    let relay_epoch = number("iam-relay-epoch")
        .and_then(|value| RelayEpoch::new(value).ok())
        .ok_or_else(malformed)?;
    Ok(TailRecord {
        offset: record.offset,
        key,
        payload,
        version,
        relay_epoch,
    })
}

fn unavailable(error: BoxError) -> PolicyLogTailError {
    PolicyLogTailError::Unavailable(error)
}

fn into_unavailable(error: KrafkaError) -> PolicyLogTailError {
    PolicyLogTailError::Unavailable(Box::new(error))
}

#[async_trait::async_trait]
impl PolicyLogTail for KrafkaPolicyLogTail {
    async fn watermark(&self) -> Result<i64, PolicyLogTailError> {
        self.checked_watermark().await
    }

    async fn read_range(
        &self,
        from: i64,
        up_to: i64,
    ) -> Result<Vec<TailRecord>, PolicyLogTailError> {
        self.range(from, up_to).await
    }

    async fn read_at(&self, offset: i64) -> Result<Option<TailRecord>, PolicyLogTailError> {
        let records = self.range(offset, offset.saturating_add(1)).await?;
        Ok(records.into_iter().find(|record| record.offset == offset))
    }

    async fn close(&self) {
        self.release().await;
    }
}

#[cfg(test)]
mod tests;
