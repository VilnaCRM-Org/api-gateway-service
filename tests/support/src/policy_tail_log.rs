//! A double of the state topic as the tail of a gateway pod follows it: a script of poll answers.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};

use async_trait::async_trait;
use iam_domain::{FramedRecord, PolicyLogTailError, PolicyTailLog, TailBatch, TimedRecord};

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Gives other tasks a turn before it completes, so an idle tail never starves them.
struct YieldOnce(bool);

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            return Poll::Ready(());
        }
        self.0 = true;
        context.waker().wake_by_ref();
        Poll::Pending
    }
}

/// One scripted answer of a poll.
#[derive(Debug)]
pub enum PollStep {
    /// The batch is returned.
    Batch(TailBatch),
    /// The cluster does not answer.
    Unavailable,
    /// The record at this offset is not a record of this service.
    Malformed(i64),
}

/// A record with the broker append time `appended_at_ms`.
#[must_use]
pub const fn timed(framed: FramedRecord, appended_at_ms: Option<i64>) -> TimedRecord {
    TimedRecord {
        framed,
        appended_at_ms,
    }
}

/// A batch of `records` over the partition bounds `low..high`.
#[must_use]
pub const fn batch(records: Vec<TimedRecord>, low: i64, high: i64) -> TailBatch {
    TailBatch { records, low, high }
}

#[derive(Debug)]
struct Script {
    steps: VecDeque<PollStep>,
    positions: Vec<i64>,
    idle_high: i64,
}

/// The state topic of a tail: the scripted answers in order, then an idle tail.
#[derive(Debug)]
pub struct FakePolicyTailLog {
    script: Mutex<Script>,
    closes: AtomicUsize,
}

impl FakePolicyTailLog {
    /// A topic that answers the polls with `steps` in order and then reports an idle tail over
    /// the bounds `0..idle_high`.
    #[must_use]
    pub fn scripted(steps: Vec<PollStep>, idle_high: i64) -> Self {
        Self {
            script: Mutex::new(Script {
                steps: steps.into(),
                positions: Vec::new(),
                idle_high,
            }),
            closes: AtomicUsize::new(0),
        }
    }

    /// The position of every poll so far, in order.
    #[must_use]
    pub fn positions(&self) -> Vec<i64> {
        locked(&self.script).positions.clone()
    }

    /// How often the connection was released.
    #[must_use]
    pub fn closes(&self) -> usize {
        self.closes.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl PolicyTailLog for FakePolicyTailLog {
    async fn poll(&self, position: i64) -> Result<TailBatch, PolicyLogTailError> {
        let step = {
            let mut script = locked(&self.script);
            script.positions.push(position);
            script.steps.pop_front().ok_or(script.idle_high)
        };
        match step {
            Ok(PollStep::Batch(batch)) => Ok(batch),
            Ok(PollStep::Unavailable) => Err(PolicyLogTailError::Unavailable(
                "the broker is unreachable".into(),
            )),
            Ok(PollStep::Malformed(offset)) => Err(PolicyLogTailError::Malformed { offset }),
            Err(high) => {
                YieldOnce(false).await;
                Ok(TailBatch {
                    records: Vec::new(),
                    low: 0,
                    high,
                })
            }
        }
    }

    async fn close(&self) {
        self.closes.fetch_add(1, Ordering::SeqCst);
    }
}
