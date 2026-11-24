//! The unit of work that makes a write wait for the Kafka acknowledgement of its policy version
//! (FR-2, FR-75).
//!
//! It commits through the unit of work it wraps and then waits for the relay's stored offset of
//! the `__head` row of the version, for at most the publish wait timeout (`PUBLISH_WAIT_TIMEOUT`).
//! The relay stores that offset at the Kafka acknowledgement with the idempotent relay and only at
//! the completed commit with the transactional relay, so what this waits for is the same in both.
//! The outcome is stored on the change receipt, where a replay with the same idempotency key finds
//! it again.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ChangeReceipt, IamChange, IamUnitOfWork, PolicyVersion, PropagationOutcome, PropagationStore,
    RepositoryError, WriteMode,
};
use shared_domain::Clock;

/// How long the wait sleeps between two looks at the stored offset.
pub const PUBLISH_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// A unit of work that waits for the publication of the version a change produced.
#[derive(Debug)]
pub struct PublishingUnitOfWork {
    inner: Arc<dyn IamUnitOfWork>,
    store: Arc<dyn PropagationStore>,
    clock: Arc<dyn Clock>,
    timeout: Duration,
}

impl PublishingUnitOfWork {
    /// A unit of work over `inner` that waits at most `timeout` for the acknowledgement.
    #[must_use]
    pub const fn new(
        inner: Arc<dyn IamUnitOfWork>,
        store: Arc<dyn PropagationStore>,
        clock: Arc<dyn Clock>,
        timeout: Duration,
    ) -> Self {
        Self {
            inner,
            store,
            clock,
            timeout,
        }
    }

    async fn commit_and_wait(
        &self,
        change: IamChange,
        write_mode: WriteMode,
    ) -> Result<ChangeReceipt, RepositoryError> {
        let receipt = self.inner.commit(change, write_mode).await?;
        let Some(version) = receipt.policy_version() else {
            return Ok(receipt);
        };
        let outcome = self.wait_for(version).await;
        self.remember(&receipt, outcome).await;
        Ok(receipt.with_propagation(outcome))
    }

    /// Stores the outcome on the receipt. A write that is committed does not fail because its
    /// outcome could not be stored; a replay then finds none.
    async fn remember(&self, receipt: &ChangeReceipt, outcome: PropagationOutcome) {
        if let Err(error) = self.store.record(receipt.change_id(), outcome).await {
            log_not_stored(&error);
        }
    }

    /// Looks for the stored offset of `version` until it appears or the timeout passes on the
    /// clock.
    async fn wait_for(&self, version: PolicyVersion) -> PropagationOutcome {
        let started = self.clock.now();
        loop {
            if let Some(outcome) = self.settled(version, started).await {
                return outcome;
            }
            tokio::time::sleep(PUBLISH_POLL_INTERVAL).await;
        }
    }

    /// The outcome when the wait is over: the offset was found, the timeout passed, or the store
    /// cannot be read, which leaves the version unconfirmed, the honest answer for a change that
    /// is committed.
    async fn settled(
        &self,
        version: PolicyVersion,
        started: SystemTime,
    ) -> Option<PropagationOutcome> {
        match self.store.published_head_offset(version).await {
            Ok(Some(offset)) => Some(PropagationOutcome::Published { offset }),
            Ok(None) => self
                .expired(started)
                .then_some(PropagationOutcome::CommittedPending),
            Err(error) => {
                log_unreadable(&error);
                Some(PropagationOutcome::CommittedPending)
            }
        }
    }

    /// Whether the timeout passed on the clock since `started`.
    fn expired(&self, started: SystemTime) -> bool {
        self.clock
            .now()
            .duration_since(started)
            .unwrap_or(Duration::ZERO)
            >= self.timeout
    }
}

/// Logs that the outcome of a committed change could not be stored.
fn log_not_stored(error: &RepositoryError) {
    tracing::warn!(%error, "the propagation outcome of a committed change was not stored");
}

/// Logs that the published offset of a policy version could not be read.
fn log_unreadable(error: &RepositoryError) {
    tracing::warn!(%error, "the published offset of a policy version could not be read");
}

#[async_trait::async_trait]
impl IamUnitOfWork for PublishingUnitOfWork {
    async fn commit(
        &self,
        change: IamChange,
        write_mode: WriteMode,
    ) -> Result<ChangeReceipt, RepositoryError> {
        self.commit_and_wait(change, write_mode).await
    }
}

#[cfg(test)]
mod tests;
