use std::sync::Arc;

use shared_domain::{Query as _, QueryHandler as _};
use test_support::policy_epoch::{FakePolicyEpochRepository, policy_epoch, seeded_policy_epoch};
use test_support::seed::TestRng;

use super::{GetPolicyEpochQuery, GetPolicyEpochQueryHandler};
use crate::error::IamError;

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(GetPolicyEpochQuery::NAME, "GetPolicyEpochQuery");
}

#[tokio::test]
async fn answers_the_seeded_epoch_of_a_new_repository() {
    let handler = GetPolicyEpochQueryHandler::new(Arc::new(FakePolicyEpochRepository::new()));

    let answer = handler.handle(GetPolicyEpochQuery).await.unwrap();

    assert_eq!(answer, seeded_policy_epoch());
}

#[tokio::test]
async fn answers_the_epoch_the_repository_holds() {
    let mut rng = TestRng::from_env();
    let epoch = policy_epoch(&mut rng);
    let handler =
        GetPolicyEpochQueryHandler::new(Arc::new(FakePolicyEpochRepository::holding(epoch)));

    let answer = handler.handle(GetPolicyEpochQuery).await.unwrap();

    assert_eq!(answer, epoch);
}

#[tokio::test]
async fn a_missing_epoch_is_not_found() {
    let handler = GetPolicyEpochQueryHandler::new(Arc::new(FakePolicyEpochRepository::empty()));

    let error = handler.handle(GetPolicyEpochQuery).await.unwrap_err();

    assert!(matches!(error, IamError::NotFound));
}

#[tokio::test]
async fn a_failing_repository_is_a_storage_error() {
    let handler = GetPolicyEpochQueryHandler::new(Arc::new(FakePolicyEpochRepository::failing()));

    let error = handler.handle(GetPolicyEpochQuery).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
