use super::RouteStatement;
use crate::route::Route;
use crate::route::fixtures::{fields, stamp};
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::http_method::HttpMethod;
use crate::value_object::identifier::RouteId;

fn route() -> Route {
    Route::create(
        RouteId::parse("00000000-0000-7000-8000-000000000001").unwrap(),
        fields("api.example.com", "/users", &[HttpMethod::Get]),
        false,
        stamp(1_700_000_000),
    )
}

#[test]
fn an_insert_carries_the_state_of_the_route_and_expects_no_version() {
    let route = route();

    let statement = RouteStatement::insert(&route);

    assert_eq!(statement.route(), route.parts());
    assert_eq!(statement.expected(), None);
}

#[test]
fn an_update_carries_the_state_of_the_route_and_the_expected_version() {
    let route = route();
    let expected = EntityVersion::new(3).unwrap();

    let statement = RouteStatement::update(&route, expected);

    assert_eq!(statement.route(), route.parts());
    assert_eq!(statement.expected(), Some(expected));
}
