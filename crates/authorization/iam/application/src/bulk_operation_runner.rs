//! The `BulkOperationRunner` singleton: commits a bulk operation in ordered chunks at most
//! `BULK_MAX_RECORDS_PER_SECOND` records per second (FR-1, FR-84).
//!
//! Each chunk is a transaction of its own, committed by the [`BulkChunkCommitter`] together with
//! the progress of the operation. Between two chunks the runner waits for the share of the rate
//! cap that the chunk used and holds no lock of the policy, so a revocation-class write commits
//! between two chunks and never waits for the bulk operation to finish. A runner that stops in
//! the middle of an operation resumes from the applied records of its stored progress.

use std::sync::Arc;
use std::time::Duration;

use iam_domain::{
    BulkChunkCommitter, BulkOperation, BulkOperationRepository, BulkPacing, BulkStamp,
    ChunkCommitError, LeaderBatch, SingletonLeadership, SingletonTask,
};
use shared_domain::{BoxError, Clock, UuidGenerator};

use crate::singleton_loop::{SingletonInterval, SingletonLoop, SingletonWork};

/// How much paced waiting one batch may take: the batch ends after the chunk that reaches it, so a
/// service that stops waits for the end of a batch for a bounded time.
const MAX_BATCH_PACING: Duration = Duration::from_secs(5);

/// How often a replica polls for a bulk operation that no wake-up announced.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// The ports of the runner.
#[derive(Debug, Clone)]
pub struct BulkRunnerPorts {
    /// Where the operations and their progress are stored.
    pub operations: Arc<dyn BulkOperationRepository>,
    /// Commits the next chunk of an operation.
    pub committer: Arc<dyn BulkChunkCommitter>,
    /// The time of a failure.
    pub clock: Arc<dyn Clock>,
    /// The identifiers of completion events.
    pub ids: Arc<dyn UuidGenerator>,
}

/// The bulk operation task: runs the oldest unfinished operation chunk by chunk.
#[derive(Debug)]
pub struct BulkOperationRunner {
    ports: BulkRunnerPorts,
    pacing: BulkPacing,
}

impl BulkOperationRunner {
    /// The task: its name in the log and in `iam_task_state`, and the constant that the advisory
    /// lock of its batches is taken on.
    pub const TASK: SingletonTask = SingletonTask::new("bulk-operation-runner", 7_009);

    /// The runner over its ports and the rate cap `BULK_MAX_RECORDS_PER_SECOND`.
    #[must_use]
    pub const fn new(ports: BulkRunnerPorts, pacing: BulkPacing) -> Self {
        Self { ports, pacing }
    }

    /// The loop that runs the task, polling every second.
    #[must_use]
    pub fn into_loop(
        self,
        leadership: Arc<dyn SingletonLeadership>,
        clock: Arc<dyn Clock>,
    ) -> SingletonLoop {
        SingletonLoop::new(
            Self::TASK,
            SingletonInterval::clamped(POLL_INTERVAL),
            leadership,
            clock,
            Arc::new(self),
        )
    }

    /// Commits chunks of the oldest unfinished operations until none is left or the batch used
    /// its share of waiting.
    async fn run_chunks(&self) -> Result<(), BoxError> {
        let mut paced = Duration::ZERO;
        while paced < MAX_BATCH_PACING {
            let Some(operation) = self.ports.operations.oldest_unfinished().await? else {
                return Ok(());
            };
            if let Some(records) = self.commit(&operation).await? {
                let wait = self.pacing.duration_of(records);
                tokio::time::sleep(wait).await;
                paced = paced.saturating_add(wait);
            }
        }
        Ok(())
    }

    /// Commits the next chunk of `operation`: the records it applied, or none when the change
    /// cannot be applied and the operation failed.
    async fn commit(&self, operation: &BulkOperation) -> Result<Option<u64>, BoxError> {
        let stamp = BulkStamp {
            event_id: self.ports.ids.generate(),
            occurred_at: self.ports.clock.now(),
        };
        match self
            .ports
            .committer
            .commit_next_chunk(operation, stamp)
            .await
        {
            Ok(chunk) => Ok(Some(chunk.records)),
            Err(ChunkCommitError::Permanent(reason)) => {
                self.fail(operation, &reason).await?;
                Ok(None)
            }
            Err(unavailable @ ChunkCommitError::Unavailable(_)) => Err(Box::new(unavailable)),
        }
    }

    /// Stores the failure of `operation`; the chunks it already committed stay.
    async fn fail(&self, operation: &BulkOperation, reason: &str) -> Result<(), BoxError> {
        let mut failed = BulkOperation::restore(operation.parts().clone())?;
        failed.fail(reason, self.ports.clock.now())?;
        self.ports.operations.save(&failed).await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl SingletonWork for BulkOperationRunner {
    async fn run(&self, _batch: &mut dyn LeaderBatch) -> Result<(), BoxError> {
        self.run_chunks().await
    }
}

#[cfg(test)]
mod tests;
