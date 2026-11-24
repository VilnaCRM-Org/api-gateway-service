use std::sync::Arc;

use iam_domain::{
    EntityVersion, RateFallback, RateKeyKind, RatePolicyDraft, RatePolicyFields, RatePolicyId,
    RatePolicyParts, RatePolicyRepository,
};
use shared_domain::{Query as _, QueryHandler as _};
use test_support::rate_policy::FakeRatePolicyRepository;

use super::{GetRatePolicyQuery, GetRatePolicyQueryHandler};
use crate::error::IamError;

const POLICY: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ae";

fn parts(deleted: bool) -> RatePolicyParts {
    RatePolicyParts {
        id: RatePolicyId::parse(POLICY).unwrap(),
        fields: RatePolicyFields::new(RatePolicyDraft {
            name: "per-ip".to_owned(),
            key_kind: RateKeyKind::Ip,
            limit: 100,
            period_seconds: 60,
            burst: 10,
            fallback: RateFallback::Divided,
        })
        .unwrap(),
        version: EntityVersion::INITIAL,
        created_at: std::time::SystemTime::UNIX_EPOCH,
        updated_at: std::time::SystemTime::UNIX_EPOCH,
        deleted_at: deleted.then_some(std::time::SystemTime::UNIX_EPOCH),
    }
}

fn handler(repository: FakeRatePolicyRepository) -> GetRatePolicyQueryHandler {
    let repository: Arc<dyn RatePolicyRepository> = Arc::new(repository);
    GetRatePolicyQueryHandler::new(repository)
}

fn query() -> GetRatePolicyQuery {
    GetRatePolicyQuery {
        id: RatePolicyId::parse(POLICY).unwrap(),
    }
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(GetRatePolicyQuery::NAME, "GetRatePolicyQuery");
}

#[tokio::test]
async fn a_stored_rate_policy_is_returned_with_its_state() {
    let handler = handler(FakeRatePolicyRepository::holding(vec![parts(false)]));

    let found = handler.handle(query()).await.unwrap();

    assert_eq!(found, Some(parts(false)));
}

#[tokio::test]
async fn an_unknown_or_deleted_rate_policy_is_none() {
    let empty = handler(FakeRatePolicyRepository::new());
    let deleted = handler(FakeRatePolicyRepository::holding(vec![parts(true)]));

    assert_eq!(empty.handle(query()).await.unwrap(), None);
    assert_eq!(deleted.handle(query()).await.unwrap(), None);
}

#[tokio::test]
async fn a_failing_storage_is_a_storage_error() {
    let handler = handler(FakeRatePolicyRepository::failing());

    let error = handler.handle(query()).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
