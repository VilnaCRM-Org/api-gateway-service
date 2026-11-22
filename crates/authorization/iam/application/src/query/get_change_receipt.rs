//! Reads the receipt of a committed change.

use std::sync::Arc;

use iam_domain::{ChangeId, ChangeReceipt, ChangeReceiptRepository};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;

/// Asks for the receipt of the change `change_id`: REST and GraphQL read it after dispatching a
/// command, which returns no data.
#[derive(Debug, Clone, Copy)]
pub struct GetChangeReceiptQuery {
    /// The change the interface layer generated for the command.
    pub change_id: ChangeId,
}

impl Query for GetChangeReceiptQuery {
    type Output = ChangeReceipt;
    type Error = IamError;
    const NAME: &'static str = "GetChangeReceiptQuery";
}

/// Handles [`GetChangeReceiptQuery`].
#[derive(Debug)]
pub struct GetChangeReceiptQueryHandler {
    repository: Arc<dyn ChangeReceiptRepository>,
}

impl GetChangeReceiptQueryHandler {
    /// A handler over the repository.
    #[must_use]
    pub const fn new(repository: Arc<dyn ChangeReceiptRepository>) -> Self {
        Self { repository }
    }

    async fn get(&self, query: GetChangeReceiptQuery) -> Result<ChangeReceipt, IamError> {
        Ok(self.repository.find(query.change_id).await?)
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetChangeReceiptQuery> for GetChangeReceiptQueryHandler {
    async fn handle(&self, query: GetChangeReceiptQuery) -> Result<ChangeReceipt, IamError> {
        self.get(query).await
    }
}

#[cfg(test)]
mod tests;
