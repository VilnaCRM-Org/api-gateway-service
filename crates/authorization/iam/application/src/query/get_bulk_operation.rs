//! Reads one bulk operation by its identifier (FR-84).

use std::sync::Arc;

use iam_domain::{BulkOperationId, BulkOperationParts, BulkOperationRepository};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;

/// Asks for the bulk operation with the identifier.
#[derive(Debug, Clone, Copy)]
pub struct GetBulkOperationQuery {
    /// The bulk operation to read.
    pub id: BulkOperationId,
}

impl Query for GetBulkOperationQuery {
    type Output = Option<BulkOperationParts>;
    type Error = IamError;
    const NAME: &'static str = "GetBulkOperationQuery";
}

/// Handles [`GetBulkOperationQuery`]: the state of the bulk operation, or none when it is unknown.
#[derive(Debug)]
pub struct GetBulkOperationQueryHandler {
    operations: Arc<dyn BulkOperationRepository>,
}

impl GetBulkOperationQueryHandler {
    /// A handler over the bulk operation repository.
    #[must_use]
    pub const fn new(operations: Arc<dyn BulkOperationRepository>) -> Self {
        Self { operations }
    }

    async fn get(
        &self,
        query: GetBulkOperationQuery,
    ) -> Result<Option<BulkOperationParts>, IamError> {
        let operation = self.operations.find(query.id).await?;
        Ok(operation.map(|operation| operation.parts().clone()))
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetBulkOperationQuery> for GetBulkOperationQueryHandler {
    async fn handle(
        &self,
        query: GetBulkOperationQuery,
    ) -> Result<Option<BulkOperationParts>, IamError> {
        self.get(query).await
    }
}

#[cfg(test)]
mod tests;
