//! Offers a refused request of an IAM operation to the buffer of the audit log (FR-49).

use std::sync::Arc;

use iam_domain::{
    ActorRef, AuditAction, AuditReason, AuditTarget, RejectedAttempt, RejectedAttemptLog, RequestId,
};
use shared_domain::{Clock, Command, CommandHandler};

use crate::error::IamError;

/// Records that `actor` was refused `action`.
///
/// The command changes no state the caller waits for: it hands the refusal to the buffer and
/// returns, and the writer appends it to the audit chain later.
#[derive(Debug, Clone)]
pub struct RecordRejectedAttemptCommand {
    /// Who made the request.
    pub actor: ActorRef,
    /// What the request tried to do.
    pub action: AuditAction,
    /// Why it was refused.
    pub reason: AuditReason,
    /// What it was aimed at.
    pub target: AuditTarget,
    /// The request id of the refused request.
    pub request_id: Option<RequestId>,
}

impl Command for RecordRejectedAttemptCommand {
    type Error = IamError;
    const NAME: &'static str = "RecordRejectedAttemptCommand";
}

/// Handles [`RecordRejectedAttemptCommand`].
///
/// It offers the attempt, stamped with the time of the `Clock` port, to the
/// [`RejectedAttemptLog`] without awaiting anything, so a refusal never waits for the chain-head
/// lock; the buffer summarises identical attempts of one actor within 60 seconds.
#[derive(Debug)]
pub struct RecordRejectedAttemptCommandHandler {
    log: Arc<dyn RejectedAttemptLog>,
    clock: Arc<dyn Clock>,
}

impl RecordRejectedAttemptCommandHandler {
    /// A handler over the buffer and the clock.
    #[must_use]
    pub const fn new(log: Arc<dyn RejectedAttemptLog>, clock: Arc<dyn Clock>) -> Self {
        Self { log, clock }
    }

    fn record(&self, command: RecordRejectedAttemptCommand) {
        self.log.offer(RejectedAttempt {
            actor: command.actor,
            action: command.action,
            reason: command.reason,
            target: command.target,
            occurred_at: self.clock.now(),
            request_id: command.request_id,
        });
    }
}

#[async_trait::async_trait]
impl CommandHandler<RecordRejectedAttemptCommand> for RecordRejectedAttemptCommandHandler {
    async fn handle(&self, command: RecordRejectedAttemptCommand) -> Result<(), IamError> {
        self.record(command);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
