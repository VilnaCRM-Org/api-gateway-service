use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, BulkKind, BulkOperation, BulkOperationId, BulkOperationRepository, SystemComponent,
};
use shared_domain::{Query as _, QueryHandler as _};
use test_support::bulk_operation::FakeBulkOperationRepository;

use super::{ListBulkOperationsQuery, ListBulkOperationsQueryHandler, MAX_PAGE_SIZE};
use crate::error::IamError;

fn id(number: u32) -> BulkOperationId {
    BulkOperationId::parse(&format!("0190f2a8-7b3c-7d4e-8f10-{number:012x}")).unwrap()
}

fn operation(number: u32) -> BulkOperation {
    BulkOperation::pending(
        id(number),
        BulkKind::Catalogue,
        10,
        ActorRef::System(SystemComponent::Startup),
        SystemTime::UNIX_EPOCH,
    )
    .unwrap()
}

fn handler(count: u32) -> ListBulkOperationsQueryHandler {
    let all: Vec<_> = (1..=count).map(operation).collect();
    let operations: Arc<dyn BulkOperationRepository> =
        Arc::new(FakeBulkOperationRepository::holding(&all));
    ListBulkOperationsQueryHandler::new(operations)
}

fn ids(page: &super::BulkOperationPage) -> Vec<BulkOperationId> {
    page.operations.iter().map(|parts| parts.id).collect()
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(ListBulkOperationsQuery::NAME, "ListBulkOperationsQuery");
}

#[tokio::test]
async fn a_page_holds_the_limit_and_points_at_the_next_one() {
    let handler = handler(3);

    let first = handler
        .handle(ListBulkOperationsQuery {
            limit: 2,
            after: None,
        })
        .await
        .unwrap();
    let second = handler
        .handle(ListBulkOperationsQuery {
            limit: 2,
            after: first.next_after,
        })
        .await
        .unwrap();

    assert_eq!(ids(&first), vec![id(1), id(2)]);
    assert_eq!(first.next_after, Some(id(2)));
    assert_eq!(ids(&second), vec![id(3)]);
    assert_eq!(second.next_after, None);
}

#[tokio::test]
async fn a_page_that_ends_exactly_at_the_limit_has_no_next_page() {
    let page = handler(2)
        .handle(ListBulkOperationsQuery {
            limit: 2,
            after: None,
        })
        .await
        .unwrap();

    assert_eq!(ids(&page), vec![id(1), id(2)]);
    assert_eq!(page.next_after, None);
}

#[tokio::test]
async fn a_limit_outside_the_range_is_brought_into_it() {
    let handler = handler(3);

    let zero = handler
        .handle(ListBulkOperationsQuery {
            limit: 0,
            after: None,
        })
        .await
        .unwrap();
    let huge = handler
        .handle(ListBulkOperationsQuery {
            limit: MAX_PAGE_SIZE + 50,
            after: None,
        })
        .await
        .unwrap();

    assert_eq!(zero.operations.len(), 1);
    assert_eq!(huge.operations.len(), 3);
}

#[tokio::test]
async fn a_failing_repository_is_a_storage_error() {
    let operations: Arc<dyn BulkOperationRepository> =
        Arc::new(FakeBulkOperationRepository::failing());
    let handler = ListBulkOperationsQueryHandler::new(operations);

    let error = handler
        .handle(ListBulkOperationsQuery {
            limit: 5,
            after: None,
        })
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
