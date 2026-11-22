use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{ActorRef, ChangeReceipt, IdempotencyRecord, IdempotencyRequest, RequestDigest};
use shared_application::http::Problem;
use shared_domain::{Query as _, QueryHandler as _};
use test_support::change_receipt::{FakeChangeReceiptRepository, change_receipt};
use test_support::clock::FixedClock;
use test_support::idempotency::{FakeIdempotencyRepository, idempotency_request};
use test_support::seed::TestRng;

use super::{GetIdempotentReplayQuery, GetIdempotentReplayQueryHandler};
use crate::error::IamError;

/// The time of the fixed clock.
fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

/// A committed change: its receipt, the request that produced it, and its idempotency record.
fn committed(rng: &mut TestRng) -> (ChangeReceipt, IdempotencyRequest, IdempotencyRecord) {
    let receipt = change_receipt(rng);
    let request = idempotency_request(rng);
    let record = IdempotencyRecord::new(
        receipt.actor().clone(),
        request.clone(),
        receipt.change_id(),
    );
    (receipt, request, record)
}

fn handler(
    keys: FakeIdempotencyRepository,
    receipts: FakeChangeReceiptRepository,
) -> (
    GetIdempotentReplayQueryHandler,
    Arc<FakeIdempotencyRepository>,
) {
    let keys = Arc::new(keys);
    let handler = GetIdempotentReplayQueryHandler::new(
        Arc::<FakeIdempotencyRepository>::clone(&keys),
        Arc::new(receipts),
        Arc::new(FixedClock::at(now())),
    );
    (handler, keys)
}

fn query(actor: &ActorRef, request: IdempotencyRequest) -> GetIdempotentReplayQuery {
    GetIdempotentReplayQuery {
        actor: actor.clone(),
        request,
    }
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(GetIdempotentReplayQuery::NAME, "GetIdempotentReplayQuery");
}

#[tokio::test]
async fn a_repeat_with_the_same_digest_within_24_hours_answers_the_original_receipt() {
    let mut rng = TestRng::from_env();
    let (receipt, request, record) = committed(&mut rng);
    let created_at = now().checked_sub(Duration::from_secs(86_399)).unwrap();
    let (handler, keys) = handler(
        FakeIdempotencyRepository::holding(vec![(record, created_at)]),
        FakeChangeReceiptRepository::holding(vec![receipt.clone()]),
    );

    let answer = handler
        .handle(query(receipt.actor(), request))
        .await
        .unwrap();

    assert_eq!(answer, Some(receipt));
    assert_eq!(
        keys.asked_since(),
        vec![now().checked_sub(Duration::from_hours(24)).unwrap()]
    );
}

#[tokio::test]
async fn a_repeat_with_another_body_within_24_hours_is_the_422_idempotency_mismatch() {
    let mut rng = TestRng::from_env();
    let (receipt, request, record) = committed(&mut rng);
    let other = IdempotencyRequest {
        key: request.key,
        request_digest: RequestDigest::new(&[0xAB; 32]).unwrap(),
    };
    let (handler, _keys) = handler(
        FakeIdempotencyRepository::holding(vec![(record, now())]),
        FakeChangeReceiptRepository::holding(vec![receipt.clone()]),
    );

    let error = handler
        .handle(query(receipt.actor(), other))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::IdempotencyMismatch));
    let problem = Problem::from(error);
    assert_eq!(problem.status, 422);
    assert_eq!(
        problem.detail.as_deref(),
        Some("The idempotency key was already used for a different request.")
    );
}

#[tokio::test]
async fn a_record_older_than_24_hours_by_the_clock_lets_the_request_run_as_new() {
    let mut rng = TestRng::from_env();
    let (receipt, request, record) = committed(&mut rng);
    let created_at = now().checked_sub(Duration::from_secs(86_401)).unwrap();
    let (handler, keys) = handler(
        FakeIdempotencyRepository::holding(vec![(record, created_at)]),
        FakeChangeReceiptRepository::holding(vec![receipt.clone()]),
    );

    let answer = handler
        .handle(query(receipt.actor(), request))
        .await
        .unwrap();

    assert_eq!(answer, None);
    assert_eq!(
        keys.asked_since(),
        vec![now().checked_sub(Duration::from_hours(24)).unwrap()]
    );
}

#[tokio::test]
async fn a_new_key_lets_the_request_run_as_new() {
    let mut rng = TestRng::from_env();
    let (receipt, request, _record) = committed(&mut rng);
    let (handler, _keys) = handler(
        FakeIdempotencyRepository::new(),
        FakeChangeReceiptRepository::holding(vec![receipt.clone()]),
    );

    let answer = handler
        .handle(query(receipt.actor(), request))
        .await
        .unwrap();

    assert_eq!(answer, None);
}

#[tokio::test]
async fn a_failing_key_repository_is_a_storage_error() {
    let mut rng = TestRng::from_env();
    let (receipt, request, _record) = committed(&mut rng);
    let (handler, _keys) = handler(
        FakeIdempotencyRepository::failing(),
        FakeChangeReceiptRepository::holding(vec![receipt.clone()]),
    );

    let error = handler
        .handle(query(receipt.actor(), request))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}

#[tokio::test]
async fn a_failing_receipt_repository_is_a_storage_error() {
    let mut rng = TestRng::from_env();
    let (receipt, request, record) = committed(&mut rng);
    let (handler, _keys) = handler(
        FakeIdempotencyRepository::holding(vec![(record, now())]),
        FakeChangeReceiptRepository::failing(),
    );

    let error = handler
        .handle(query(receipt.actor(), request))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}

#[tokio::test]
async fn a_record_without_its_receipt_is_not_found() {
    let mut rng = TestRng::from_env();
    let (receipt, request, record) = committed(&mut rng);
    let (handler, _keys) = handler(
        FakeIdempotencyRepository::holding(vec![(record, now())]),
        FakeChangeReceiptRepository::new(),
    );

    let error = handler
        .handle(query(receipt.actor(), request))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::NotFound));
}
