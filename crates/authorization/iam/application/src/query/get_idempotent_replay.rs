//! Finds the change that a repeated idempotent write replays (FR-2).

use std::sync::Arc;

use iam_domain::{
    ActorRef, ChangeReceipt, ChangeReceiptRepository, IdempotencyRecord, IdempotencyRepository,
    IdempotencyRequest,
};
use shared_domain::{Clock, Query, QueryHandler};

use crate::error::IamError;

/// Asks whether the write `request` of `actor` repeats a change committed in the last 24 hours.
#[derive(Debug, Clone)]
pub struct GetIdempotentReplayQuery {
    /// Who sends the write.
    pub actor: ActorRef,
    /// The idempotency key and the request digest of the write.
    pub request: IdempotencyRequest,
}

impl Query for GetIdempotentReplayQuery {
    type Output = Option<ChangeReceipt>;
    type Error = IamError;
    const NAME: &'static str = "GetIdempotentReplayQuery";
}

/// Handles [`GetIdempotentReplayQuery`].
///
/// It answers the original receipt when the actor used the key for the
/// same request within [`IdempotencyRecord::WINDOW`] by the `Clock` port, none when the key is new
/// or its record expired (the write then runs as a new change), and
/// [`IamError::IdempotencyMismatch`] when the key was used for another request.
#[derive(Debug)]
pub struct GetIdempotentReplayQueryHandler {
    keys: Arc<dyn IdempotencyRepository>,
    receipts: Arc<dyn ChangeReceiptRepository>,
    clock: Arc<dyn Clock>,
}

impl GetIdempotentReplayQueryHandler {
    /// A handler over the two repositories and the clock.
    #[must_use]
    pub const fn new(
        keys: Arc<dyn IdempotencyRepository>,
        receipts: Arc<dyn ChangeReceiptRepository>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            keys,
            receipts,
            clock,
        }
    }

    async fn find(
        &self,
        query: GetIdempotentReplayQuery,
    ) -> Result<Option<ChangeReceipt>, IamError> {
        let since = IdempotencyRecord::window_start(self.clock.now());
        let stored = self
            .keys
            .find_since(&query.actor, &query.request.key, since)
            .await?;
        let Some(record) = stored else {
            return Ok(None);
        };
        let change_id = record
            .replay(query.request.request_digest)
            .ok_or(IamError::IdempotencyMismatch)?;
        Ok(Some(self.receipts.find(change_id).await?))
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetIdempotentReplayQuery> for GetIdempotentReplayQueryHandler {
    async fn handle(
        &self,
        query: GetIdempotentReplayQuery,
    ) -> Result<Option<ChangeReceipt>, IamError> {
        self.find(query).await
    }
}

#[cfg(test)]
mod tests;
