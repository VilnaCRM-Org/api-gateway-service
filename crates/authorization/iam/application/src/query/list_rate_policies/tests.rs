use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    EntityVersion, RateFallback, RateKeyKind, RatePolicyDraft, RatePolicyFields, RatePolicyId,
    RatePolicyParts, RatePolicyRepository,
};
use shared_domain::{Query as _, QueryHandler as _};
use test_support::rate_policy::FakeRatePolicyRepository;

use super::{ListRatePoliciesQuery, ListRatePoliciesQueryHandler, MAX_PAGE_SIZE, RatePolicyPage};
use crate::error::IamError;

fn id(number: u32) -> RatePolicyId {
    RatePolicyId::parse(&format!("0190f2a8-7b3c-7d4e-8f10-{number:012x}")).unwrap()
}

fn parts(number: u32) -> RatePolicyParts {
    RatePolicyParts {
        id: id(number),
        fields: RatePolicyFields::new(RatePolicyDraft {
            name: format!("policy-{number}"),
            key_kind: RateKeyKind::Route,
            limit: 100,
            period_seconds: 60,
            burst: 0,
            fallback: RateFallback::Full,
        })
        .unwrap(),
        version: EntityVersion::INITIAL,
        created_at: SystemTime::UNIX_EPOCH,
        updated_at: SystemTime::UNIX_EPOCH,
        deleted_at: None,
    }
}

fn numbered(count: u32) -> Vec<RatePolicyParts> {
    (1..=count).map(parts).collect()
}

fn handler(policies: Vec<RatePolicyParts>) -> ListRatePoliciesQueryHandler {
    let repository: Arc<dyn RatePolicyRepository> =
        Arc::new(FakeRatePolicyRepository::holding(policies));
    ListRatePoliciesQueryHandler::new(repository)
}

fn query(limit: u32) -> ListRatePoliciesQuery {
    ListRatePoliciesQuery { limit, after: None }
}

fn ids(page: &RatePolicyPage) -> Vec<RatePolicyId> {
    page.rate_policies.iter().map(|policy| policy.id).collect()
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(ListRatePoliciesQuery::NAME, "ListRatePoliciesQuery");
}

#[tokio::test]
async fn a_page_smaller_than_the_stock_names_the_last_policy_as_its_cursor() {
    let handler = handler(numbered(5));

    let page = handler.handle(query(2)).await.unwrap();

    assert_eq!(ids(&page), [id(1), id(2)]);
    assert_eq!(page.next_after, Some(id(2)));
}

#[tokio::test]
async fn following_the_cursors_visits_every_policy_exactly_once() {
    let handler = handler(numbered(5));
    let mut seen = Vec::new();
    let mut after = None;

    loop {
        let page = handler
            .handle(ListRatePoliciesQuery { after, ..query(2) })
            .await
            .unwrap();
        seen.extend(ids(&page));
        after = page.next_after;
        if after.is_none() {
            break;
        }
    }

    assert_eq!(seen, [id(1), id(2), id(3), id(4), id(5)]);
}

#[tokio::test]
async fn the_last_page_has_no_cursor() {
    let handler = handler(numbered(2));

    let page = handler.handle(query(2)).await.unwrap();

    assert_eq!(ids(&page), [id(1), id(2)]);
    assert_eq!(page.next_after, None);
}

#[tokio::test]
async fn a_limit_outside_the_range_is_brought_into_it() {
    let handler = handler(numbered(105));

    let none = handler.handle(query(0)).await.unwrap();
    let many = handler.handle(query(1_000)).await.unwrap();

    assert_eq!(none.rate_policies.len(), 1);
    assert_eq!(
        many.rate_policies.len(),
        usize::try_from(MAX_PAGE_SIZE).unwrap()
    );
    assert!(many.next_after.is_some());
}

#[tokio::test]
async fn a_failing_storage_is_a_storage_error() {
    let repository: Arc<dyn RatePolicyRepository> = Arc::new(FakeRatePolicyRepository::failing());
    let handler = ListRatePoliciesQueryHandler::new(repository);

    let error = handler.handle(query(5)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
