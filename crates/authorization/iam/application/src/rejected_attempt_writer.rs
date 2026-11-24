//! The per-replica loop that appends buffered refusals to the audit chain (FR-49).

use std::sync::Arc;
use std::time::Duration;

use iam_domain::{
    AttemptSummary, AuditOutcome, AuditSummary, InvalidIamValue, RejectedAttemptLog,
    RepositoryError, SecurityAuditEvent, SecurityAuditEventId, SecurityAuditEventParts,
    SecurityAuditLog,
};
use shared_domain::{Clock, UuidGenerator};
use tokio::sync::watch;

/// How often the writer appends what the buffer holds: at most once a second, so the chain-head
/// lock is taken at most once a second per replica however many requests were refused.
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(1);

/// How a flush ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushOutcome {
    /// Nothing was due.
    Idle,
    /// This many records were appended in one batch.
    Appended(usize),
    /// The append failed; the summaries went back to the buffer.
    Failed,
}

/// Appends the refusals that [`RejectedAttemptLog`] holds to the [`SecurityAuditLog`] in batches.
///
/// Every replica runs its own writer; none needs the singleton lock, because the append itself
/// takes the chain-head lock. A summary that cannot be appended goes back to the buffer and is
/// tried again at the next flush; when the service stops, the writer flushes once more.
#[derive(Debug)]
pub struct RejectedAttemptWriter {
    log: Arc<dyn RejectedAttemptLog>,
    audit: Arc<dyn SecurityAuditLog>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn UuidGenerator>,
}

impl RejectedAttemptWriter {
    /// A writer from the buffer to the audit log.
    #[must_use]
    pub const fn new(
        log: Arc<dyn RejectedAttemptLog>,
        audit: Arc<dyn SecurityAuditLog>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            log,
            audit,
            clock,
            ids,
        }
    }

    /// Appends the summaries that are due now, as one batch.
    pub async fn flush(&self) -> FlushOutcome {
        let summaries = self.log.drain(self.clock.now());
        if summaries.is_empty() {
            return FlushOutcome::Idle;
        }
        match self.events_of(&summaries) {
            Ok(events) => self.append(events, summaries).await,
            Err(error) => {
                log_undescribed(error);
                FlushOutcome::Failed
            }
        }
    }

    /// Appends `events`; when that fails, `summaries` go back to the buffer.
    async fn append(
        &self,
        events: Vec<SecurityAuditEvent>,
        summaries: Vec<AttemptSummary>,
    ) -> FlushOutcome {
        match self.audit.append_batch(&events).await {
            Ok(_head) => FlushOutcome::Appended(events.len()),
            Err(error) => {
                log_not_appended(&error);
                self.log.requeue(summaries);
                FlushOutcome::Failed
            }
        }
    }

    /// Flushes every second until the stop flag is set or its sender is gone, then once more.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        while !*shutdown.borrow() {
            self.flush().await;
            if !Self::pause(&mut shutdown).await {
                break;
            }
        }
        self.flush().await;
    }

    /// Waits for the interval; `false` when the service is stopping instead.
    async fn pause(shutdown: &mut watch::Receiver<bool>) -> bool {
        tokio::select! {
            () = tokio::time::sleep(FLUSH_INTERVAL) => true,
            stopping = shutdown.wait_for(|stopping| *stopping) => {
                drop(stopping);
                false
            }
        }
    }

    /// One `Rejected` record per summary, in the order of the summaries.
    fn events_of(
        &self,
        summaries: &[AttemptSummary],
    ) -> Result<Vec<SecurityAuditEvent>, InvalidIamValue> {
        summaries
            .iter()
            .map(|summary| self.event_of(summary))
            .collect()
    }

    fn event_of(&self, summary: &AttemptSummary) -> Result<SecurityAuditEvent, InvalidIamValue> {
        let first = summary.first();
        SecurityAuditEvent::record(SecurityAuditEventParts {
            id: SecurityAuditEventId::from_uuid(self.ids.generate()),
            occurred_at: first.occurred_at,
            actor: first.actor.clone(),
            caller_service: None,
            action: first.action.clone(),
            target: first.target.clone(),
            scope: None,
            before: None,
            after: Some(AuditSummary::new(&format!("attempts={}", summary.count()))?),
            idempotency_key: None,
            outcome: AuditOutcome::Rejected,
            reason: Some(first.reason.clone()),
            policy_version: None,
            request_id: first.request_id.clone(),
        })
    }
}

fn log_undescribed(error: InvalidIamValue) {
    tracing::error!(error = %error, "rejected attempts could not be recorded");
}

fn log_not_appended(error: &RepositoryError) {
    tracing::warn!(error = %error, "rejected attempts could not be appended");
}

#[cfg(test)]
mod tests;
