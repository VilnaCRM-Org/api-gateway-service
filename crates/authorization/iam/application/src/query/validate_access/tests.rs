use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    AccessCheck, AccessTarget, Credential, Decision, DecisionReason, PermissionsTarget,
    PolicyEpochRepository, PolicyReadRepository, PolicyVersion, ServiceName, TokenRejection,
};
use shared_domain::{Query as _, QueryHandler as _};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::policy_epoch::FakePolicyEpochRepository;
use test_support::policy_read::FakePolicyReadRepository;
use test_support::token::FakeTokenRepository;

use super::{ValidateAccessQuery, ValidateAccessQueryHandler};
use crate::access_decision_service::AccessDecisionService;
use crate::error::IamError;
use crate::service_catalog_loader::ServiceCatalogLoader;

fn check(minimum: Option<i64>) -> AccessCheck {
    AccessCheck::new(
        ServiceName::new("orders").unwrap(),
        AccessTarget::Permissions(
            PermissionsTarget::new(vec!["rest:orders:GET /api/orders".to_owned()]).unwrap(),
        ),
        None,
        minimum.map(|value| PolicyVersion::new(value).unwrap()),
    )
}

fn query(minimum: Option<i64>) -> ValidateAccessQuery {
    ValidateAccessQuery {
        credential: Credential::new("refused".to_owned()),
        check: check(minimum),
    }
}

fn handler(epochs: impl PolicyEpochRepository + 'static) -> ValidateAccessQueryHandler {
    let policy: Arc<dyn PolicyReadRepository> = Arc::new(FakePolicyReadRepository::new());
    let tokens = FakeTokenRepository::new().rejecting("refused", TokenRejection::Expired);
    let decisions = AccessDecisionService::new(
        Arc::new(tokens),
        ServiceCatalogLoader::new(Arc::clone(&policy)),
        policy,
        Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );
    ValidateAccessQueryHandler::new(Arc::new(decisions), Arc::new(epochs))
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(ValidateAccessQuery::NAME, "ValidateAccessQuery");
}

#[test]
fn the_query_does_not_print_the_credential() {
    let printed = format!("{:?}", query(None));

    assert!(!printed.contains("refused"), "{printed}");
}

#[tokio::test]
async fn a_check_without_a_minimum_version_is_decided_without_reading_the_epoch() {
    let handler = handler(FakePolicyEpochRepository::failing());

    let outcome = handler.handle(query(None)).await.unwrap();

    assert_eq!(outcome.decision(), Decision::Deny);
    assert_eq!(outcome.reason(), DecisionReason::TokenExpired);
}

#[tokio::test]
async fn a_minimum_version_equal_to_the_current_one_is_decided() {
    let handler = handler(FakePolicyEpochRepository::new());

    let outcome = handler.handle(query(Some(0))).await.unwrap();

    assert_eq!(outcome.reason(), DecisionReason::TokenExpired);
}

#[tokio::test]
async fn a_minimum_version_above_the_current_one_is_a_violation_of_the_caller() {
    let handler = handler(FakePolicyEpochRepository::new());

    let error = handler.handle(query(Some(1))).await.unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("expected a violation, got {error:?}");
    };
    let [violation] = violations.as_slice() else {
        panic!("expected one violation, got {violations:?}");
    };
    assert_eq!(violation.property_path, "minPolicyVersion");
    assert_eq!(violation.code, "range");
}

#[tokio::test]
async fn an_epoch_that_cannot_be_read_is_the_deny_unavailable() {
    let handler = handler(FakePolicyEpochRepository::failing());

    let outcome = handler.handle(query(Some(1))).await.unwrap();

    assert_eq!(outcome.decision(), Decision::Deny);
    assert_eq!(outcome.reason(), DecisionReason::Unavailable);
    assert_eq!(outcome.subject(), None);
    assert_eq!(outcome.policy_version(), None);
}

#[tokio::test]
async fn a_missing_epoch_is_the_deny_unavailable() {
    let handler = handler(FakePolicyEpochRepository::empty());

    let outcome = handler.handle(query(Some(1))).await.unwrap();

    assert_eq!(outcome.reason(), DecisionReason::Unavailable);
}
