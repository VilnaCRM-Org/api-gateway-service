use std::sync::Arc;

use shared_domain::{Query as _, QueryHandler as _};
use test_support::change_receipt::{FakeChangeReceiptRepository, change_receipt};
use test_support::seed::TestRng;

use super::{GetChangeReceiptQuery, GetChangeReceiptQueryHandler};
use crate::error::IamError;

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(GetChangeReceiptQuery::NAME, "GetChangeReceiptQuery");
}

#[tokio::test]
async fn answers_the_receipt_of_the_change() {
    let mut rng = TestRng::from_env();
    let other = change_receipt(&mut rng);
    let receipt = change_receipt(&mut rng);
    let repository = FakeChangeReceiptRepository::holding(vec![other, receipt.clone()]);
    let handler = GetChangeReceiptQueryHandler::new(Arc::new(repository));

    let answer = handler
        .handle(GetChangeReceiptQuery {
            change_id: receipt.change_id(),
        })
        .await
        .unwrap();

    assert_eq!(answer, receipt);
}

#[tokio::test]
async fn an_unknown_change_is_not_found() {
    let receipt = change_receipt(&mut TestRng::from_env());
    let handler = GetChangeReceiptQueryHandler::new(Arc::new(FakeChangeReceiptRepository::new()));

    let error = handler
        .handle(GetChangeReceiptQuery {
            change_id: receipt.change_id(),
        })
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::NotFound));
}

#[tokio::test]
async fn a_failing_repository_is_a_storage_error() {
    let receipt = change_receipt(&mut TestRng::from_env());
    let handler =
        GetChangeReceiptQueryHandler::new(Arc::new(FakeChangeReceiptRepository::failing()));

    let error = handler
        .handle(GetChangeReceiptQuery {
            change_id: receipt.change_id(),
        })
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
