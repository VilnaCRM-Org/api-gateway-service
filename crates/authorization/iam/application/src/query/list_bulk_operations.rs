//! Lists bulk operations with cursor pagination, oldest first (FR-84).

use std::sync::Arc;

use iam_domain::{BulkOperationId, BulkOperationParts, BulkOperationRepository};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;

/// The largest page of bulk operations.
pub const MAX_PAGE_SIZE: u32 = 100;

/// Asks for one page of the bulk operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListBulkOperationsQuery {
    /// The largest number of operations of the page; a value outside 1 to [`MAX_PAGE_SIZE`] is
    /// brought into that range.
    pub limit: u32,
    /// The last operation of the previous page; none for the first page.
    pub after: Option<BulkOperationId>,
}

/// One page of bulk operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkOperationPage {
    /// The operations of the page, oldest first.
    pub operations: Vec<BulkOperationParts>,
    /// The cursor of the next page: the last operation of this one; none when none follows.
    pub next_after: Option<BulkOperationId>,
}

impl Query for ListBulkOperationsQuery {
    type Output = BulkOperationPage;
    type Error = IamError;
    const NAME: &'static str = "ListBulkOperationsQuery";
}

/// Handles [`ListBulkOperationsQuery`].
///
/// It reads one operation more than the page holds, to know whether another page follows without a
/// second query.
#[derive(Debug)]
pub struct ListBulkOperationsQueryHandler {
    operations: Arc<dyn BulkOperationRepository>,
}

impl ListBulkOperationsQueryHandler {
    /// A handler over the bulk operation repository.
    #[must_use]
    pub const fn new(operations: Arc<dyn BulkOperationRepository>) -> Self {
        Self { operations }
    }

    async fn list(&self, query: ListBulkOperationsQuery) -> Result<BulkOperationPage, IamError> {
        let limit = query.limit.clamp(1, MAX_PAGE_SIZE);
        let mut operations: Vec<BulkOperationParts> = self
            .operations
            .list(query.after, limit.saturating_add(1))
            .await?
            .iter()
            .map(|operation| operation.parts().clone())
            .collect();
        let size = usize::try_from(limit).unwrap_or(usize::MAX);
        let next_after = operations
            .get(size.saturating_sub(1))
            .filter(|_last| operations.len() > size)
            .map(|last| last.id);
        operations.truncate(size);
        Ok(BulkOperationPage {
            operations,
            next_after,
        })
    }
}

#[async_trait::async_trait]
impl QueryHandler<ListBulkOperationsQuery> for ListBulkOperationsQueryHandler {
    async fn handle(&self, query: ListBulkOperationsQuery) -> Result<BulkOperationPage, IamError> {
        self.list(query).await
    }
}

#[cfg(test)]
mod tests;
