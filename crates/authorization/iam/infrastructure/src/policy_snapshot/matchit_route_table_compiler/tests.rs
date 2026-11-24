use std::time::SystemTime;

use iam_domain::{
    EntityVersion, HttpMethod, RouteConflict, RouteFields, RouteHost, RouteId, RouteParts,
    UpstreamId,
};
use shared_domain::Uuid;
use test_support::route::route_draft;

use super::*;

fn uuid(last: u8) -> Uuid {
    Uuid::parse(&format!("0192f6a0-0000-7000-8000-0000000000{last:02x}")).unwrap()
}

fn route(last: u8, host: &str, pattern: &str, methods: &[HttpMethod]) -> RouteParts {
    let draft = route_draft(
        host,
        pattern,
        methods,
        "users",
        UpstreamId::from_uuid(uuid(200)),
    );
    RouteParts {
        id: RouteId::from_uuid(uuid(last)),
        fields: RouteFields::new(&draft).unwrap(),
        system: false,
        version: EntityVersion::INITIAL,
        created_at: SystemTime::UNIX_EPOCH,
        updated_at: SystemTime::UNIX_EPOCH,
        deleted_at: None,
    }
}

fn host() -> RouteHost {
    RouteHost::new("api.example.com").unwrap()
}

fn id(last: u8) -> RouteId {
    RouteId::from_uuid(uuid(last))
}

#[test]
fn it_finds_a_route_by_method_and_path() {
    let routes = [
        route(
            1,
            "api.example.com",
            "/users",
            &[HttpMethod::Get, HttpMethod::Post],
        ),
        route(2, "api.example.com", "/users/{id}", &[HttpMethod::Get]),
        route(3, "api.example.com", "/files/{path:*}", &[HttpMethod::Get]),
        route(4, "api.example.com", "/", &[HttpMethod::Get]),
    ];

    let matcher = MatchitRouteTableCompiler.compile(&host(), &routes).unwrap();

    assert_eq!(matcher.find(HttpMethod::Get, "/users"), Some(id(1)));
    assert_eq!(matcher.find(HttpMethod::Post, "/users"), Some(id(1)));
    assert_eq!(matcher.find(HttpMethod::Get, "/users/7"), Some(id(2)));
    assert_eq!(matcher.find(HttpMethod::Get, "/files/a/b/c"), Some(id(3)));
    assert_eq!(matcher.find(HttpMethod::Get, "/"), Some(id(4)));
    assert_eq!(matcher.find(HttpMethod::Delete, "/users"), None);
    assert_eq!(matcher.find(HttpMethod::Get, "/missing"), None);
}

#[test]
fn it_prefers_a_literal_segment_over_a_parameter() {
    let routes = [
        route(1, "api.example.com", "/users/{id}", &[HttpMethod::Get]),
        route(2, "api.example.com", "/users/me", &[HttpMethod::Get]),
    ];

    let matcher = MatchitRouteTableCompiler.compile(&host(), &routes).unwrap();

    assert_eq!(matcher.find(HttpMethod::Get, "/users/me"), Some(id(2)));
    assert_eq!(matcher.find(HttpMethod::Get, "/users/7"), Some(id(1)));
}

#[test]
fn it_ignores_the_routes_of_other_hosts() {
    let routes = [
        route(1, "api.example.com", "/users", &[HttpMethod::Get]),
        route(2, "other.example.com", "/users", &[HttpMethod::Get]),
    ];

    let matcher = MatchitRouteTableCompiler.compile(&host(), &routes).unwrap();

    assert_eq!(matcher.find(HttpMethod::Get, "/users"), Some(id(1)));
}

#[test]
fn it_reports_two_routes_of_the_same_shape_as_a_conflict() {
    let routes = [
        route(1, "api.example.com", "/users/{id}", &[HttpMethod::Get]),
        route(2, "api.example.com", "/users/{name}", &[HttpMethod::Get]),
    ];

    let error = MatchitRouteTableCompiler
        .compile(&host(), &routes)
        .unwrap_err();

    assert!(matches!(error, RouteConflict::SamePattern { .. }));
}

#[test]
fn routes_of_the_same_shape_with_other_methods_do_not_conflict() {
    let routes = [
        route(1, "api.example.com", "/users/{id}", &[HttpMethod::Get]),
        route(2, "api.example.com", "/users/{name}", &[HttpMethod::Post]),
    ];

    let matcher = MatchitRouteTableCompiler.compile(&host(), &routes).unwrap();

    assert_eq!(matcher.find(HttpMethod::Post, "/users/x"), Some(id(2)));
}

#[test]
fn routes_that_name_the_same_position_differently_compile_on_one_host() {
    let routes = [
        route(1, "api.example.com", "/a/{x}", &[HttpMethod::Get]),
        route(2, "api.example.com", "/a/{y}/b", &[HttpMethod::Get]),
        route(3, "api.example.com", "/a/{z}/b/{w}", &[HttpMethod::Get]),
    ];

    let matcher = MatchitRouteTableCompiler.compile(&host(), &routes).unwrap();

    assert_eq!(matcher.find(HttpMethod::Get, "/a/1"), Some(id(1)));
    assert_eq!(matcher.find(HttpMethod::Get, "/a/1/b"), Some(id(2)));
    assert_eq!(matcher.find(HttpMethod::Get, "/a/1/b/2"), Some(id(3)));
}

#[test]
fn two_routes_of_one_shape_conflict_whatever_their_parameter_names() {
    let routes = [
        route(1, "api.example.com", "/a/{x}", &[HttpMethod::Get]),
        route(2, "api.example.com", "/a/{y}", &[HttpMethod::Get]),
    ];

    let error = MatchitRouteTableCompiler
        .compile(&host(), &routes)
        .unwrap_err();

    assert_eq!(
        error,
        RouteConflict::SamePattern {
            first: id(1),
            second: id(2)
        }
    );
}

#[test]
fn a_catch_all_after_parameters_is_named_by_its_position() {
    let routes = [route(
        1,
        "api.example.com",
        "/f/{a}/{rest:*}",
        &[HttpMethod::Get],
    )];

    let matcher = MatchitRouteTableCompiler.compile(&host(), &routes).unwrap();

    assert_eq!(matcher.find(HttpMethod::Get, "/f/1/x/y"), Some(id(1)));
}
