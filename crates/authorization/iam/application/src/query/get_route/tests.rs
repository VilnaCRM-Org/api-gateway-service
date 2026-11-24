use std::sync::Arc;

use iam_domain::{HttpMethod, RouteParts, RouteRepository};
use shared_domain::{Query as _, QueryHandler as _};
use test_support::route::FakeRouteRepository;

use super::{GetRouteQuery, GetRouteQueryHandler};
use crate::error::IamError;
use crate::route_fixtures::{numbered_id, route_at};

fn parts(number: u32) -> RouteParts {
    route_at(
        numbered_id(number),
        &format!("/api/route-{number}"),
        &[HttpMethod::Get],
        1,
    )
}

fn handler(routes: FakeRouteRepository) -> GetRouteQueryHandler {
    let routes: Arc<dyn RouteRepository> = Arc::new(routes);
    GetRouteQueryHandler::new(routes)
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(GetRouteQuery::NAME, "GetRouteQuery");
}

#[tokio::test]
async fn a_stored_route_is_answered_with_its_state() {
    let handler = handler(FakeRouteRepository::holding(vec![parts(1), parts(2)]));

    let answer = handler
        .handle(GetRouteQuery { id: numbered_id(2) })
        .await
        .unwrap();

    assert_eq!(answer, Some(parts(2)));
}

#[tokio::test]
async fn an_unknown_route_is_answered_with_none() {
    let handler = handler(FakeRouteRepository::holding(vec![parts(1)]));

    let answer = handler
        .handle(GetRouteQuery { id: numbered_id(9) })
        .await
        .unwrap();

    assert_eq!(answer, None);
}

#[tokio::test]
async fn a_deleted_route_is_answered_with_none() {
    let mut deleted = parts(1);
    deleted.deleted_at = Some(deleted.created_at);
    let handler = handler(FakeRouteRepository::holding(vec![deleted]));

    let answer = handler
        .handle(GetRouteQuery { id: numbered_id(1) })
        .await
        .unwrap();

    assert_eq!(answer, None);
}

#[tokio::test]
async fn a_storage_failure_is_the_error_of_the_query() {
    let handler = handler(FakeRouteRepository::failing());

    let error = handler
        .handle(GetRouteQuery { id: numbered_id(1) })
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
