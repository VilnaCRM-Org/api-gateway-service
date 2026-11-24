use std::sync::Arc;

use iam_domain::{UpstreamId, UpstreamParts, UpstreamRepository};
use shared_domain::{Query as _, QueryHandler as _};
use test_support::upstream::FakeUpstreamRepository;

use super::{ListUpstreamsQuery, ListUpstreamsQueryHandler, MAX_PAGE_SIZE, UpstreamPage};
use crate::error::IamError;
use crate::upstream_fixtures::upstream_named;

fn id(number: u32) -> UpstreamId {
    UpstreamId::parse(&format!("0190f2a8-7b3c-7d4e-8f10-{number:012x}")).unwrap()
}

fn numbered(count: u32) -> Vec<UpstreamParts> {
    (1..=count)
        .map(|number| upstream_named(id(number), &format!("upstream-{number}"), "core", 1))
        .collect()
}

fn handler(upstreams: FakeUpstreamRepository) -> ListUpstreamsQueryHandler {
    let upstreams: Arc<dyn UpstreamRepository> = Arc::new(upstreams);
    ListUpstreamsQueryHandler::new(upstreams)
}

fn query(limit: u32) -> ListUpstreamsQuery {
    ListUpstreamsQuery { limit, after: None }
}

fn ids(page: &UpstreamPage) -> Vec<UpstreamId> {
    page.upstreams.iter().map(|upstream| upstream.id).collect()
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(ListUpstreamsQuery::NAME, "ListUpstreamsQuery");
}

#[tokio::test]
async fn a_page_smaller_than_the_stock_names_the_last_upstream_as_its_cursor() {
    let handler = handler(FakeUpstreamRepository::holding(numbered(5)));

    let page = handler.handle(query(2)).await.unwrap();

    assert_eq!(ids(&page), [id(1), id(2)]);
    assert_eq!(page.next_after, Some(id(2)));
}

#[tokio::test]
async fn following_the_cursors_visits_every_upstream_exactly_once() {
    let handler = handler(FakeUpstreamRepository::holding(numbered(5)));
    let mut seen = Vec::new();
    let mut after = None;

    loop {
        let page = handler
            .handle(ListUpstreamsQuery { after, ..query(2) })
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
async fn a_page_that_holds_the_rest_has_no_cursor() {
    let handler = handler(FakeUpstreamRepository::holding(numbered(2)));

    let page = handler.handle(query(2)).await.unwrap();

    assert_eq!(ids(&page), [id(1), id(2)]);
    assert_eq!(page.next_after, None);
}

#[tokio::test]
async fn a_limit_of_zero_reads_one_upstream() {
    let handler = handler(FakeUpstreamRepository::holding(numbered(3)));

    let page = handler.handle(query(0)).await.unwrap();

    assert_eq!(ids(&page), [id(1)]);
    assert_eq!(page.next_after, Some(id(1)));
}

#[tokio::test]
async fn a_limit_above_the_maximum_reads_the_largest_page() {
    let count = MAX_PAGE_SIZE + 5;
    let handler = handler(FakeUpstreamRepository::holding(numbered(count)));

    let page = handler.handle(query(count)).await.unwrap();

    assert_eq!(
        page.upstreams.len(),
        usize::try_from(MAX_PAGE_SIZE).unwrap()
    );
    assert_eq!(page.next_after, Some(id(MAX_PAGE_SIZE)));
}

#[tokio::test]
async fn a_storage_failure_is_the_error_of_the_query() {
    let handler = handler(FakeUpstreamRepository::failing());

    let error = handler.handle(query(5)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
