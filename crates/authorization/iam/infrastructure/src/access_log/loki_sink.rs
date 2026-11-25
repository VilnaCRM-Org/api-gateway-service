//! The sink of the audit lane: batches pushed to Loki, with the answer of Loki kept for the
//! writer (Story 14.2, FR-50, NFR-24).
//!
//! The writer thread hands entries to [`LokiPushAccessLogSink::write`], which only queues them. A
//! worker thread of the sink pushes the queue every flush interval, or at once when it holds a
//! mebibyte, through a [`LokiTransport`]. A batch that Loki acknowledged (a 2xx answer) counts in
//! [`AccessLogSink::acknowledged_audit`]; a batch that failed goes back to the front of the queue
//! and is pushed again, so an entry is pushed again only until Loki has acknowledged it, and never
//! after.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use iam_domain::{AccessEntry, AccessLane, AccessLogSink};

use self::payload::{PendingLine, pending_of, push_body};

mod payload;

/// The size at which a batch is pushed without waiting for the flush interval: one mebibyte.
pub const BATCH_BYTES: usize = 1_048_576;

/// The name of the worker thread.
pub const WORKER_THREAD: &str = "access-log-loki";

/// Sends one push request to Loki; the part of the sink that touches the network.
pub trait LokiTransport: std::fmt::Debug + Send + Sync {
    /// Posts `body`, the JSON of a push request, to Loki and waits for the answer. `true` when
    /// Loki acknowledged the batch; `false` for any failure, which leaves the batch to be pushed
    /// again.
    fn push(&self, body: &str) -> bool;
}

/// What the sink labels its streams with and how often it pushes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LokiSinkSettings {
    /// The value of the `app` label.
    pub app: String,
    /// The value of the `env` label.
    pub env: String,
    /// How long entries wait in the queue before they are pushed.
    pub flush_interval: Duration,
}

/// The entries that have not been pushed, oldest first.
#[derive(Debug, Default)]
struct Queue {
    lines: Vec<PendingLine>,
    bytes: usize,
}

impl Queue {
    fn push(&mut self, line: PendingLine) {
        self.bytes = self.bytes.saturating_add(line.size());
        self.lines.push(line);
    }

    /// Takes the oldest lines, as many as fit into one batch and at least one.
    fn take_batch(&mut self) -> Vec<PendingLine> {
        let mut size = 0_usize;
        let mut count = 0_usize;
        for line in &self.lines {
            if count > 0 && size.saturating_add(line.size()) > BATCH_BYTES {
                break;
            }
            size = size.saturating_add(line.size());
            count = count.saturating_add(1);
        }
        let rest = self.lines.split_off(count);
        let batch = std::mem::replace(&mut self.lines, rest);
        self.bytes = self.bytes.saturating_sub(size);
        batch
    }

    /// Puts a batch that was not acknowledged back in front of the lines that arrived since.
    fn restore(&mut self, mut batch: Vec<PendingLine>) {
        let bytes = batch
            .iter()
            .map(PendingLine::size)
            .fold(0_usize, usize::saturating_add);
        batch.append(&mut self.lines);
        self.lines = batch;
        self.bytes = self.bytes.saturating_add(bytes);
    }
}

/// What the writer side and the worker thread share.
#[derive(Debug)]
struct Shared {
    queue: Mutex<Queue>,
    wake: Condvar,
    acknowledged: AtomicU64,
    stopping: AtomicBool,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits until the interval is over, the queue holds a batch or the sink stops. After a failed
    /// push only the stop ends the wait early, so Loki is not asked again before the interval.
    fn wait(&self, interval: Duration, failed: bool) {
        let guard = self.lock();
        let keep_waiting = |queue: &mut Queue| {
            !self.stopping.load(Ordering::Acquire) && (failed || queue.bytes < BATCH_BYTES)
        };
        drop(
            self.wake
                .wait_timeout_while(guard, interval, keep_waiting)
                .unwrap_or_else(PoisonError::into_inner),
        );
    }

    /// Pushes one batch; `None` when nothing waited, otherwise whether Loki acknowledged it.
    fn push_batch(
        &self,
        settings: &LokiSinkSettings,
        transport: &dyn LokiTransport,
    ) -> Option<bool> {
        let batch = self.lock().take_batch();
        if batch.is_empty() {
            return None;
        }
        let body = push_body(&settings.app, &settings.env, &batch);
        let acknowledged = transport.push(&body);
        if acknowledged {
            let count = u64::try_from(batch.len()).unwrap_or(u64::MAX);
            self.acknowledged.fetch_add(count, Ordering::AcqRel);
        } else {
            self.lock().restore(batch);
        }
        Some(acknowledged)
    }

    /// Pushes batches until the queue is empty or a push fails; whether the last push failed.
    fn drain(&self, settings: &LokiSinkSettings, transport: &dyn LokiTransport) -> bool {
        loop {
            match self.push_batch(settings, transport) {
                Some(true) => {}
                Some(false) => return true,
                None => return false,
            }
        }
    }

    /// Tells the worker to push what is queued once more and end. The flag is set under the lock
    /// of the queue, so a worker that is about to wait sees it.
    fn stop(&self) {
        let queue = self.lock();
        self.stopping.store(true, Ordering::Release);
        drop(queue);
        self.wake.notify_all();
    }

    fn run(&self, settings: &LokiSinkSettings, transport: &dyn LokiTransport) {
        let mut failed = false;
        while !self.stopping.load(Ordering::Acquire) {
            self.wait(settings.flush_interval, failed);
            failed = self.drain(settings, transport);
        }
        self.drain(settings, transport);
    }
}

/// Pushes the entries of the audit lane to Loki and reports which of them Loki acknowledged.
#[derive(Debug)]
pub struct LokiPushAccessLogSink {
    shared: Arc<Shared>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl LokiPushAccessLogSink {
    /// Starts the worker thread that pushes through `transport`.
    ///
    /// # Errors
    ///
    /// The error of the operating system when the thread cannot be started.
    pub fn start(
        settings: LokiSinkSettings,
        transport: Arc<dyn LokiTransport>,
    ) -> std::io::Result<Self> {
        let shared = Arc::new(Shared {
            queue: Mutex::new(Queue::default()),
            wake: Condvar::new(),
            acknowledged: AtomicU64::new(0),
            stopping: AtomicBool::new(false),
        });
        let worker = Arc::clone(&shared);
        let handle = std::thread::Builder::new()
            .name(WORKER_THREAD.to_owned())
            .spawn(move || worker.run(&settings, transport.as_ref()))?;
        Ok(Self {
            shared,
            worker: Mutex::new(Some(handle)),
        })
    }

    /// Stops the worker after one last attempt to push what is queued, and waits for it. A second
    /// call does nothing.
    fn stop(&self) {
        self.shared.stop();
        let handle = self
            .worker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if handle.is_some_and(|handle| handle.join().is_err()) {
            log_worker_panicked();
        }
    }
}

fn log_worker_panicked() {
    tracing::error!("the access log Loki worker panicked");
}

impl AccessLogSink for LokiPushAccessLogSink {
    fn write(&self, lane: AccessLane, entry: &AccessEntry) {
        let pending = pending_of(lane, entry);
        let mut queue = self.shared.lock();
        queue.push(pending);
        if queue.bytes >= BATCH_BYTES {
            self.shared.wake.notify_all();
        }
    }

    fn acknowledged_audit(&self) -> Option<u64> {
        Some(self.shared.acknowledged.load(Ordering::Acquire))
    }

    fn flush(&self) {
        self.stop();
    }
}

impl Drop for LokiPushAccessLogSink {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests;
