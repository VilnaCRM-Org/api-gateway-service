//! The tail of the `PolicyTail` task (FR-71, FR-72, NFR-35).
//!
//! After the bootstrap a pod follows the state topic in order. [`TailMachine`] is the pure step
//! function `(state, input) -> (state, actions)` of that loop: it keeps the position of the pod in
//! memory, judges what only the batch itself can show (a position outside the partition, a
//! watermark that moved backwards, a record the broker appended more than an hour ago) and hands
//! the raw records to the apply thread, which assembles the versions, checks the digest of each
//! one before it publishes it and reports the faults of the log that need the applied state: a
//! gap, a lower log epoch, conflicting content for a version.
//!
//! Every fault of the log is a [`FenceCause`]: the tail stops, the pod keeps its last verified
//! snapshot and rebootstraps after a random delay ([`rebootstrap_delay`]). [`run_tail`] is the
//! driver that executes the actions against the port and the apply thread.

mod run;

use std::time::Duration;

use iam_domain::{FramedRecord, Rng, TailBatch};

pub use run::{ApplyResult, TailApplier, TailEnd, TailPorts, run_tail};

/// The oldest broker append time that the tail accepts, in milliseconds.
pub const MAX_APPEND_AGE_MS: i64 = 3_600_000;

/// Why the tail stopped: a fault of the log that no decision may rest on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FenceCause {
    /// A record of an applied version carries other content than the one applied.
    #[error("a record of an applied version carries conflicting content")]
    ConflictingContent,
    /// A record carries a log epoch lower than the one the pod follows.
    #[error("a record carries a log epoch lower than the one followed")]
    LowerLogEpoch,
    /// Versions are missing between the applied one and the record's.
    #[error("version {expected} is missing from the log")]
    Gap {
        /// The version that had to come next.
        expected: i64,
    },
    /// The broker appended a record too long ago for a tail that follows the live log.
    #[error("a record was appended {age_ms} ms ago, older than the tail accepts")]
    StaleAppendTime {
        /// The age of the record in milliseconds.
        age_ms: i64,
    },
    /// The watermark of the partition went backwards.
    #[error("the watermark went back from {seen} to {high}")]
    WatermarkRegression {
        /// The highest watermark seen.
        seen: i64,
        /// The watermark the broker reports now.
        high: i64,
    },
    /// The position of the tail is outside the offsets the partition holds.
    #[error("position {position} is outside the partition range {low}..{high}")]
    OutOfRange {
        /// The position of the tail.
        position: i64,
        /// The first offset the partition holds.
        low: i64,
        /// The watermark.
        high: i64,
    },
    /// The digest that a complete version leads to is not the one it carries.
    #[error("the digest at version {version} does not match its head")]
    DigestMismatch {
        /// The version.
        version: i64,
    },
    /// A record of the topic is not a record of this service.
    #[error("the record at offset {offset} is malformed")]
    Malformed {
        /// The offset of the record.
        offset: i64,
    },
    /// A complete version cannot be applied.
    #[error("a complete version cannot be applied: {0}")]
    Unappliable(String),
}

/// What the driver tells the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailInput {
    /// The tail begins.
    Start,
    /// The answer of a poll, with the wall time of the pod in milliseconds since the epoch.
    Polled {
        /// The batch.
        batch: TailBatch,
        /// The time the batch arrived.
        now_ms: i64,
    },
    /// The apply thread applied the last batch.
    Applied,
    /// The apply thread met a fault of the log.
    ApplyFenced(FenceCause),
    /// The last poll failed; the connection is reopened by the next one.
    ReadFailed(String),
    /// The record at this offset is not a record of this service.
    Unreadable {
        /// The offset of the record.
        offset: i64,
    },
}

/// What the machine asks the driver to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailAction {
    /// Poll the topic for the records at or after the position.
    Poll {
        /// The position.
        position: i64,
    },
    /// Hand these raw records to the apply thread.
    Apply(Vec<FramedRecord>),
    /// Pause before the next poll.
    Backoff,
    /// Stop: the log cannot be trusted.
    Fence(FenceCause),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Following,
    Fenced,
}

/// The tail state machine.
#[derive(Debug, Clone)]
pub struct TailMachine {
    phase: Phase,
    position: i64,
    high_seen: i64,
    aged_from: i64,
}

impl TailMachine {
    /// A machine that follows the topic from `position`, which is where the bootstrap says the tail
    /// starts. The append time is judged for the records from `aged_from` on, the offset after the
    /// last record the bootstrap read.
    #[must_use]
    pub const fn new(position: i64, aged_from: i64) -> Self {
        Self {
            phase: Phase::Following,
            position,
            high_seen: position,
            aged_from,
        }
    }

    /// The offset of the next record the tail reads.
    #[must_use]
    pub const fn position(&self) -> i64 {
        self.position
    }

    /// The step function: the next state and the actions the input asks for.
    #[must_use]
    pub fn step(mut self, input: TailInput) -> (Self, Vec<TailAction>) {
        let actions = if self.phase == Phase::Fenced {
            Vec::new()
        } else {
            self.advance(input)
        };
        (self, actions)
    }

    fn advance(&mut self, input: TailInput) -> Vec<TailAction> {
        match input {
            TailInput::Start | TailInput::Applied => vec![self.poll()],
            TailInput::Polled { batch, now_ms } => self.polled(batch, now_ms),
            TailInput::ApplyFenced(cause) => self.fence(cause),
            TailInput::ReadFailed(_reason) => vec![TailAction::Backoff, self.poll()],
            TailInput::Unreadable { offset } => self.fence(FenceCause::Malformed { offset }),
        }
    }

    const fn poll(&self) -> TailAction {
        TailAction::Poll {
            position: self.position,
        }
    }

    fn fence(&mut self, cause: FenceCause) -> Vec<TailAction> {
        self.phase = Phase::Fenced;
        vec![TailAction::Fence(cause)]
    }

    fn polled(&mut self, batch: TailBatch, now_ms: i64) -> Vec<TailAction> {
        if let Some(cause) = self.bounds_fault(&batch) {
            return self.fence(cause);
        }
        if let Some(cause) = self.age_fault(&batch, now_ms) {
            return self.fence(cause);
        }
        self.high_seen = self.high_seen.max(batch.high);
        let Some(last) = batch.records.last().map(|record| record.framed.offset) else {
            return vec![self.poll()];
        };
        self.position = last.saturating_add(1);
        let records = batch
            .records
            .into_iter()
            .map(|record| record.framed)
            .collect();
        vec![TailAction::Apply(records)]
    }

    /// The faults the bounds of the partition show. A batch with records reports only the offset
    /// after its last record as `high`, a lower bound of the watermark, so only an empty batch,
    /// which carries the true watermark, can show a regression.
    const fn bounds_fault(&self, batch: &TailBatch) -> Option<FenceCause> {
        if self.position < batch.low || self.position > batch.high {
            return Some(FenceCause::OutOfRange {
                position: self.position,
                low: batch.low,
                high: batch.high,
            });
        }
        if batch.records.is_empty() && batch.high < self.high_seen {
            return Some(FenceCause::WatermarkRegression {
                seen: self.high_seen,
                high: batch.high,
            });
        }
        None
    }

    fn age_fault(&self, batch: &TailBatch, now_ms: i64) -> Option<FenceCause> {
        batch
            .records
            .iter()
            .filter(|record| record.framed.offset >= self.aged_from)
            .filter_map(|record| record.appended_at_ms)
            .map(|appended| now_ms.saturating_sub(appended))
            .find(|age| *age > MAX_APPEND_AGE_MS)
            .map(|age_ms| FenceCause::StaleAppendTime { age_ms })
    }
}

/// The delay before a fenced pod rebootstraps: uniform in `0..=ready_bound`, drawn through `rng`,
/// so that the pods that met the same fault do not read the topic at the same moment.
#[must_use]
pub fn rebootstrap_delay(rng: &dyn Rng, ready_bound: Duration) -> Duration {
    let bound_ms = u64::try_from(ready_bound.as_millis()).unwrap_or(u64::MAX);
    let draw = rng
        .next_u64()
        .checked_rem(bound_ms.saturating_add(1))
        .unwrap_or_default();
    Duration::from_millis(draw)
}

#[cfg(test)]
mod tests;
