use std::sync::Arc;

use iam_domain::{HttpMethod, RouteHost, RouteId, RouteParts, RouteRepository, ServiceName};
use shared_domain::{Query as _, QueryHandler as _};
use test_support::route::FakeRouteRepository;

use super::{ListRoutesQuery, ListRoutesQueryHandler, MAX_PAGE_SIZE, RoutePage};
use crate::error::IamError;
use crate::route_fixtures::{numbered_id, route_at, upstream_id};

fn numbered(count: u32) -> Vec<RouteParts> {
    (1..=count)
        .map(|number| {
            route_at(
                numbered_id(number),
                &format!("/api/route-{number}"),
                &[HttpMethod::Get],
                1,
            )
        })
        .collect()
}

fn handler(routes: FakeRouteRepository) -> ListRoutesQueryHandler {
    let routes: Arc<dyn RouteRepository> = Arc::new(routes);
    ListRoutesQueryHandler::new(routes)
}

fn query(limit: u32) -> ListRoutesQuery {
    ListRoutesQuery {
        limit,
        after: None,
        host: None,
        upstream: None,
        service: None,
    }
}

fn ids(page: &RoutePage) -> Vec<RouteId> {
    page.routes.iter().map(|route| route.id).collect()
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(ListRoutesQuery::NAME, "ListRoutesQuery");
}

#[tokio::test]
async fn a_page_smaller_than_the_stock_names_the_last_route_as_its_cursor() {
    let handler = handler(FakeRouteRepository::holding(numbered(5)));

    let page = handler.handle(query(2)).await.unwrap();

    assert_eq!(ids(&page), [numbered_id(1), numbered_id(2)]);
    assert_eq!(page.next_after, Some(numbered_id(2)));
}

#[tokio::test]
async fn following_the_cursors_visits_every_route_exactly_once() {
    let handler = handler(FakeRouteRepository::holding(numbered(5)));
    let mut seen = Vec::new();
    let mut after = None;

    loop {
        let page = handler
            .handle(ListRoutesQuery { after, ..query(2) })
            .await
            .unwrap();
        seen.extend(ids(&page));
        after = page.next_after;
        if after.is_none() {
            break;
        }
    }

    assert_eq!(seen, (1..=5).map(numbered_id).collect::<Vec<_>>());
}

#[tokio::test]
async fn a_page_that_holds_the_rest_has_no_cursor() {
    let handler = handler(FakeRouteRepository::holding(numbered(2)));

    let page = handler.handle(query(2)).await.unwrap();

    assert_eq!(page.next_after, None);
}

#[tokio::test]
async fn the_filters_keep_only_the_routes_that_match() {
    let handler = handler(FakeRouteRepository::holding(numbered(3)));

    let by_host = handler
        .handle(ListRoutesQuery {
            host: Some(RouteHost::new("other.example.test").unwrap()),
            ..query(10)
        })
        .await
        .unwrap();
    let by_upstream = handler
        .handle(ListRoutesQuery {
            upstream: Some(upstream_id()),
            ..query(10)
        })
        .await
        .unwrap();
    let by_service = handler
        .handle(ListRoutesQuery {
            service: Some(ServiceName::new("payment").unwrap()),
            ..query(10)
        })
        .await
        .unwrap();

    assert_eq!(ids(&by_host), Vec::<RouteId>::new());
    assert_eq!(by_upstream.routes.len(), 3);
    assert_eq!(ids(&by_service), Vec::<RouteId>::new());
}

#[tokio::test]
async fn a_limit_of_zero_reads_one_route() {
    let handler = handler(FakeRouteRepository::holding(numbered(3)));

    let page = handler.handle(query(0)).await.unwrap();

    assert_eq!(ids(&page), [numbered_id(1)]);
}

#[tokio::test]
async fn a_limit_above_the_maximum_reads_the_largest_page() {
    let count = MAX_PAGE_SIZE + 5;
    let handler = handler(FakeRouteRepository::holding(numbered(count)));

    let page = handler.handle(query(count)).await.unwrap();

    assert_eq!(page.routes.len(), usize::try_from(MAX_PAGE_SIZE).unwrap());
}

#[tokio::test]
async fn a_storage_failure_is_the_error_of_the_query() {
    let handler = handler(FakeRouteRepository::failing());

    let error = handler.handle(query(5)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
