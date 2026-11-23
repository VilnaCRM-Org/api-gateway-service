use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    AccessCheck, AccessTarget, Credential, Decision, DecisionOutcome, DecisionReason,
    PermissionsTarget, PolicyEpochRepository, PolicyReadRepository, PolicyVersion, ServiceName,
    TokenRejection,
};
use shared_domain::{Query as _, QueryHandler as _};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::policy_epoch::FakePolicyEpochRepository;
use test_support::policy_read::FakePolicyReadRepository;
use test_support::token::FakeTokenRepository;

use super::{BatchCheck, ValidateAccessBatchQuery, ValidateAccessBatchQueryHandler};
use crate::access_decision_service::AccessDecisionService;
use crate::query::validate_access::ValidateAccessQuery;
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

fn item(credential: &str, minimum: Option<i64>) -> BatchCheck {
    BatchCheck::Valid(ValidateAccessQuery {
        credential: Credential::new(credential.to_owned()),
        check: check(minimum),
    })
}

fn tokens() -> Arc<FakeTokenRepository> {
    Arc::new(
        FakeTokenRepository::new()
            .rejecting("expired", TokenRejection::Expired)
            .rejecting("revoked", TokenRejection::Revoked),
    )
}

fn handler(
    tokens: &Arc<FakeTokenRepository>,
    epochs: impl PolicyEpochRepository + 'static,
) -> ValidateAccessBatchQueryHandler {
    let policy: Arc<dyn PolicyReadRepository> = Arc::new(FakePolicyReadRepository::new());
    let decisions = AccessDecisionService::new(
        Arc::<FakeTokenRepository>::clone(tokens),
        ServiceCatalogLoader::new(Arc::clone(&policy)),
        policy,
        Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );
    ValidateAccessBatchQueryHandler::new(
        Arc::new(decisions),
        Arc::new(epochs),
        Arc::<FakeTokenRepository>::clone(tokens),
    )
}

async fn decide(
    handler: &ValidateAccessBatchQueryHandler,
    checks: Vec<BatchCheck>,
) -> Vec<DecisionOutcome> {
    handler
        .handle(ValidateAccessBatchQuery { checks })
        .await
        .unwrap()
}

fn reasons(outcomes: &[DecisionOutcome]) -> Vec<DecisionReason> {
    outcomes.iter().map(DecisionOutcome::reason).collect()
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(ValidateAccessBatchQuery::NAME, "ValidateAccessBatchQuery");
}

#[test]
fn the_query_does_not_print_a_credential() {
    let query = ValidateAccessBatchQuery {
        checks: vec![item("expired", None)],
    };

    let printed = format!("{query:?}");

    assert!(!printed.contains("expired"), "{printed}");
}

#[tokio::test]
async fn every_item_gets_a_decision_in_request_order() {
    let tokens = tokens();
    let handler = handler(&tokens, FakePolicyEpochRepository::new());

    let outcomes = decide(
        &handler,
        vec![item("expired", None), item("revoked", None), item("", None)],
    )
    .await;

    assert_eq!(
        reasons(&outcomes),
        vec![
            DecisionReason::TokenExpired,
            DecisionReason::TokenRevoked,
            DecisionReason::TokenMissing,
        ]
    );
}

#[tokio::test]
async fn every_item_has_its_own_decision_id() {
    let tokens = tokens();
    let handler = handler(&tokens, FakePolicyEpochRepository::new());

    let outcomes = decide(
        &handler,
        vec![
            item("expired", None),
            item("expired", None),
            BatchCheck::Malformed,
        ],
    )
    .await;

    let [first, second, third] = outcomes.as_slice() else {
        panic!("expected three outcomes, got {outcomes:?}");
    };
    assert_ne!(first.decision_id(), second.decision_id());
    assert_ne!(second.decision_id(), third.decision_id());
    assert_ne!(first.decision_id(), third.decision_id());
}

#[tokio::test]
async fn a_malformed_item_is_a_deny_that_does_not_fail_the_others() {
    let tokens = tokens();
    let handler = handler(&tokens, FakePolicyEpochRepository::new());

    let outcomes = decide(
        &handler,
        vec![
            item("expired", None),
            BatchCheck::Malformed,
            item("revoked", None),
        ],
    )
    .await;

    assert_eq!(
        reasons(&outcomes),
        vec![
            DecisionReason::TokenExpired,
            DecisionReason::MalformedOperation,
            DecisionReason::TokenRevoked,
        ]
    );
    let malformed = &outcomes[1];
    assert_eq!(malformed.decision(), Decision::Deny);
    assert_eq!(malformed.denied(), Vec::<String>::new());
    assert_eq!(malformed.subject(), None);
    assert_eq!(malformed.policy_version(), None);
}

#[tokio::test]
async fn a_malformed_item_resolves_no_credential() {
    let tokens = tokens();
    let handler = handler(&tokens, FakePolicyEpochRepository::new());

    let _outcomes = decide(&handler, vec![BatchCheck::Malformed, BatchCheck::Malformed]).await;

    assert_eq!(tokens.calls(), 0);
}

#[tokio::test]
async fn two_distinct_credentials_across_fifty_checks_are_resolved_twice() {
    let tokens = tokens();
    let handler = handler(&tokens, FakePolicyEpochRepository::new());
    let checks = (0..50)
        .map(|index| item(if index % 2 == 0 { "expired" } else { "revoked" }, None))
        .collect();

    let outcomes = decide(&handler, checks).await;

    assert_eq!(outcomes.len(), 50);
    assert_eq!(tokens.calls(), 2);
}

#[tokio::test]
async fn a_second_batch_resolves_its_credentials_again() {
    let tokens = tokens();
    let handler = handler(&tokens, FakePolicyEpochRepository::new());

    let _first = decide(&handler, vec![item("expired", None)]).await;
    let _second = decide(&handler, vec![item("expired", None)]).await;

    assert_eq!(tokens.calls(), 2);
}

#[tokio::test]
async fn a_version_that_iam_has_not_issued_is_a_malformed_item() {
    let tokens = tokens();
    let handler = handler(&tokens, FakePolicyEpochRepository::new());

    let outcomes = decide(
        &handler,
        vec![item("expired", Some(1)), item("expired", Some(0))],
    )
    .await;

    assert_eq!(
        reasons(&outcomes),
        vec![
            DecisionReason::MalformedOperation,
            DecisionReason::TokenExpired
        ]
    );
    assert_eq!(tokens.calls(), 1);
}

#[tokio::test]
async fn an_epoch_that_cannot_be_read_is_the_deny_unavailable_for_that_item() {
    let tokens = tokens();
    let handler = handler(&tokens, FakePolicyEpochRepository::failing());

    let outcomes = decide(
        &handler,
        vec![item("expired", Some(1)), item("expired", None)],
    )
    .await;

    assert_eq!(
        reasons(&outcomes),
        vec![DecisionReason::Unavailable, DecisionReason::TokenExpired]
    );
}

#[tokio::test]
async fn an_empty_batch_has_no_decision() {
    let tokens = tokens();
    let handler = handler(&tokens, FakePolicyEpochRepository::new());

    let outcomes = decide(&handler, Vec::new()).await;

    assert_eq!(outcomes, []);
}
