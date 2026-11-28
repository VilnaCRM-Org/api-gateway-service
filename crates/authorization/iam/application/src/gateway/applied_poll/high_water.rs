//! The last stable offset `HW0` that the bootstrap of the pod captured (FR-76, Story 13.3).
//!
//! A bootstrap reads the state topic from offset 0 up to `HW0`, so every record below it is in the
//! state the pod publishes. A write whose offset lies below `HW0` is therefore covered by the
//! bootstrap, and a pod that is still bootstrapping can tell the Sync-Fence coordinator so at once.
//! [`RecordingBootstrapLog`] watches the capture without changing what the bootstrap reads.

use std::sync::Arc;

use iam_domain::{FramedRecord, PolicyBootstrapLog, PolicyLogTailError};
use tokio::sync::watch;

/// The record before any capture.
const NOTHING_CAPTURED: i64 = -1;

/// The highest offset the bootstraps of the pod captured as the end of the topic.
#[derive(Debug)]
pub struct BootstrapHighWater {
    captured: watch::Sender<i64>,
}

impl Default for BootstrapHighWater {
    fn default() -> Self {
        Self::new()
    }
}

impl BootstrapHighWater {
    /// A record in which nothing was captured.
    #[must_use]
    pub fn new() -> Self {
        Self {
            captured: watch::Sender::new(NOTHING_CAPTURED),
        }
    }

    /// Records the end of the topic that a bootstrap captured. The record never goes down.
    pub fn capture(&self, end: i64) {
        self.captured.send_if_modified(|held| {
            let moves = end > *held;
            if moves {
                *held = end;
            }
            moves
        });
    }

    /// Whether a captured end lies beyond `offset`, so that the record at `offset` is read by the
    /// bootstrap.
    #[must_use]
    pub fn covers(&self, offset: i64) -> bool {
        *self.captured.borrow() > offset
    }

    /// Completes once a captured end lies beyond `offset`.
    pub async fn covered(&self, offset: i64) {
        let mut record = self.captured.subscribe();
        drop(record.wait_for(|held| *held > offset).await);
    }
}

/// A bootstrap log that notes the end of the topic every capture returns, and otherwise leaves
/// every call to the log it wraps.
#[derive(Debug)]
pub struct RecordingBootstrapLog {
    inner: Arc<dyn PolicyBootstrapLog>,
    high_water: Arc<BootstrapHighWater>,
}

impl RecordingBootstrapLog {
    /// `inner`, with each captured end noted in `high_water`.
    #[must_use]
    pub fn new(inner: Arc<dyn PolicyBootstrapLog>, high_water: Arc<BootstrapHighWater>) -> Self {
        Self { inner, high_water }
    }

    async fn capture(&self) -> Result<i64, PolicyLogTailError> {
        let end = self.inner.stable_end().await?;
        self.high_water.capture(end);
        Ok(end)
    }

    async fn read(&self, from: i64, up_to: i64) -> Result<Vec<FramedRecord>, PolicyLogTailError> {
        self.inner.read_framed(from, up_to).await
    }

    async fn release(&self) {
        self.inner.close().await;
    }
}

#[async_trait::async_trait]
impl PolicyBootstrapLog for RecordingBootstrapLog {
    async fn stable_end(&self) -> Result<i64, PolicyLogTailError> {
        self.capture().await
    }

    async fn read_framed(
        &self,
        from: i64,
        up_to: i64,
    ) -> Result<Vec<FramedRecord>, PolicyLogTailError> {
        self.read(from, up_to).await
    }

    async fn close(&self) {
        self.release().await;
    }
}

#[cfg(test)]
mod tests;
