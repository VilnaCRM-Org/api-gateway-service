use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, BulkKind, BulkOperation, BulkOperationId, BulkOperationRepository, SystemComponent,
};
use shared_domain::{Query as _, QueryHandler as _};
use test_support::bulk_operation::FakeBulkOperationRepository;

use super::{GetBulkOperationQuery, GetBulkOperationQueryHandler};
use crate::error::IamError;

fn id(number: u32) -> BulkOperationId {
    BulkOperationId::parse(&format!("0190f2a8-7b3c-7d4e-8f10-{number:012x}")).unwrap()
}

fn operation(number: u32) -> BulkOperation {
    BulkOperation::pending(
        id(number),
        BulkKind::RoleDeletion,
        2_500,
        ActorRef::System(SystemComponent::Startup),
        SystemTime::UNIX_EPOCH,
    )
    .unwrap()
}

fn handler(operations: FakeBulkOperationRepository) -> GetBulkOperationQueryHandler {
    let operations: Arc<dyn BulkOperationRepository> = Arc::new(operations);
    GetBulkOperationQueryHandler::new(operations)
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(GetBulkOperationQuery::NAME, "GetBulkOperationQuery");
}

#[tokio::test]
async fn a_stored_operation_is_answered_with_its_state() {
    let handler = handler(FakeBulkOperationRepository::holding(&[
        operation(1),
        operation(2),
    ]));

    let answer = handler
        .handle(GetBulkOperationQuery { id: id(2) })
        .await
        .unwrap();

    assert_eq!(answer, Some(operation(2).parts().clone()));
}

#[tokio::test]
async fn an_unknown_operation_is_answered_with_none() {
    let handler = handler(FakeBulkOperationRepository::new());

    let answer = handler
        .handle(GetBulkOperationQuery { id: id(9) })
        .await
        .unwrap();

    assert_eq!(answer, None);
}

#[tokio::test]
async fn a_failing_repository_is_a_storage_error() {
    let handler = handler(FakeBulkOperationRepository::failing());

    let error = handler
        .handle(GetBulkOperationQuery { id: id(1) })
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
