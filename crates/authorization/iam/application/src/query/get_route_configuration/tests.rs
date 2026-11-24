use std::sync::Arc;

use iam_domain::{HttpMethod, RouteRepository, RouteSetVersion};
use shared_domain::QueryHandler as _;
use test_support::route::FakeRouteRepository;

use super::{GetRouteConfigurationQuery, GetRouteConfigurationQueryHandler};
use crate::error::IamError;
use crate::route_fixtures::{HOST, numbered_id, route_at};
use shared_domain::Query as _;

fn handler(routes: Vec<iam_domain::RouteParts>) -> GetRouteConfigurationQueryHandler {
    let repository: Arc<dyn RouteRepository> = Arc::new(FakeRouteRepository::holding(routes));
    GetRouteConfigurationQueryHandler::new(repository)
}

fn query(host: &str) -> GetRouteConfigurationQuery {
    GetRouteConfigurationQuery {
        host: host.to_owned(),
    }
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(
        GetRouteConfigurationQuery::NAME,
        "GetRouteConfigurationQuery"
    );
}

#[tokio::test]
async fn the_routes_of_the_host_come_by_path_and_methods_with_the_version_of_the_set() {
    let stored = vec![
        route_at(numbered_id(2), "/b", &[HttpMethod::Get], 3),
        route_at(numbered_id(1), "/a", &[HttpMethod::Post], 3),
        route_at(numbered_id(3), "/a", &[HttpMethod::Get], 3),
    ];

    let configuration = handler(stored.clone()).handle(query(HOST)).await.unwrap();

    let paths: Vec<(&str, &[HttpMethod])> = configuration
        .routes
        .iter()
        .map(|route| (route.fields.path_pattern().as_str(), route.fields.methods()))
        .collect();
    assert_eq!(
        paths,
        [
            ("/a", &[HttpMethod::Get][..]),
            ("/a", &[HttpMethod::Post][..]),
            ("/b", &[HttpMethod::Get][..])
        ]
    );
    assert_eq!(configuration.host.to_string(), HOST);
    assert_eq!(configuration.version, RouteSetVersion::of(&stored));
}

#[tokio::test]
async fn a_host_without_routes_has_an_empty_set() {
    let configuration = handler(Vec::new()).handle(query(HOST)).await.unwrap();

    assert_eq!(configuration.routes, Vec::new());
    assert_eq!(configuration.version, RouteSetVersion::of(&[]));
}

#[tokio::test]
async fn a_text_that_is_not_a_host_is_a_violation_of_host() {
    let error = handler(Vec::new())
        .handle(query("Not A Host"))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Invalid(_)));
}
