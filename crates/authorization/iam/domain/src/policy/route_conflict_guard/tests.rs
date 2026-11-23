use proptest::prelude::{Just, Strategy, any, prop_assert_eq, prop_oneof, proptest};
use proptest::sample::subsequence;

use super::RouteConflictGuard;
use crate::error::RouteConflict;
use crate::route::RouteParts;
use crate::route::fields::RouteFields;
use crate::route::fixtures::{draft, parts, route_id};
use crate::route::settings::{RouteFlag, RouteFlags};
use crate::value_object::http_method::HttpMethod;

const HOST: &str = "api.example.com";

fn on(host: &str, number: u32, path: &str, methods: &[HttpMethod], anonymous: bool) -> RouteParts {
    let mut route = draft(host, path, methods);
    route.flags = RouteFlags::default().with(RouteFlag::Anonymous, anonymous);
    parts(number, RouteFields::new(&route).unwrap())
}

fn route(number: u32, path: &str, methods: &[HttpMethod], anonymous: bool) -> RouteParts {
    on(HOST, number, path, methods, anonymous)
}

fn same_pattern(first: u32, second: u32) -> RouteConflict {
    RouteConflict::SamePattern {
        first: route_id(first),
        second: route_id(second),
    }
}

#[test]
fn the_same_pattern_with_intersecting_methods_conflicts() {
    let first = route(
        1,
        "/api/orders",
        &[HttpMethod::Get, HttpMethod::Post],
        false,
    );
    let second = route(
        2,
        "/api/orders",
        &[HttpMethod::Post, HttpMethod::Put],
        false,
    );

    assert_eq!(
        RouteConflictGuard::check_pair(&first, &second),
        Err(same_pattern(1, 2))
    );
    assert_eq!(
        RouteConflictGuard::check_pair(&second, &first),
        Err(same_pattern(2, 1))
    );
    assert_eq!(same_pattern(1, 2).code(), "same_pattern");
}

#[test]
fn the_same_pattern_with_disjoint_methods_is_accepted() {
    let first = route(1, "/api/orders", &[HttpMethod::Get], false);
    let second = route(2, "/api/orders", &[HttpMethod::Delete], false);

    assert_eq!(RouteConflictGuard::check_pair(&first, &second), Ok(()));
}

#[test]
fn parameter_names_do_not_make_patterns_different() {
    let first = route(1, "/api/orders/{id}", &[HttpMethod::Get], false);
    let second = route(2, "/api/orders/{order}", &[HttpMethod::Get], false);

    assert_eq!(
        RouteConflictGuard::check_pair(&first, &second),
        Err(same_pattern(1, 2))
    );
}

#[test]
fn a_host_configuration_with_a_conflicting_pair_is_refused_as_a_set() {
    let routes = [
        route(1, "/api/health", &[HttpMethod::Get], false),
        route(
            2,
            "/api/orders",
            &[HttpMethod::Get, HttpMethod::Post],
            false,
        ),
        route(
            3,
            "/api/orders",
            &[HttpMethod::Post, HttpMethod::Put],
            false,
        ),
    ];

    assert_eq!(
        RouteConflictGuard::check_set(&routes),
        Err(same_pattern(2, 3))
    );
    assert_eq!(RouteConflictGuard::check_set(&routes[..2]), Ok(()));
    assert_eq!(RouteConflictGuard::check_set(&[]), Ok(()));
}

#[test]
fn an_anonymous_catch_all_shadows_a_protected_route() {
    let anonymous = route(1, "/api/{rest:*}", &[HttpMethod::Get], true);
    let protected = route(2, "/api/orders", &[HttpMethod::Post], false);
    let conflict = RouteConflict::AnonymousShadow {
        anonymous: route_id(1),
        protected: route_id(2),
    };

    assert_eq!(
        RouteConflictGuard::check_pair(&anonymous, &protected),
        Err(conflict)
    );
    assert_eq!(
        RouteConflictGuard::check_pair(&protected, &anonymous),
        Err(conflict)
    );
    assert_eq!(conflict.code(), "anonymous_shadow");
    assert_eq!(
        RouteConflictGuard::check_set(&[protected, anonymous]),
        Err(conflict)
    );
}

#[test]
fn an_anonymous_parameter_segment_shadows_a_protected_literal() {
    let anonymous = route(1, "/api/{name}", &[HttpMethod::Get], true);
    let protected = route(2, "/api/orders", &[HttpMethod::Get], false);

    assert!(RouteConflictGuard::check_pair(&anonymous, &protected).is_err());
}

#[test]
fn two_protected_routes_with_nested_patterns_are_accepted() {
    let broad = route(1, "/api/{rest:*}", &[HttpMethod::Get], false);
    let narrow = route(2, "/api/orders", &[HttpMethod::Get], false);

    assert_eq!(RouteConflictGuard::check_pair(&broad, &narrow), Ok(()));
}

#[test]
fn a_protected_catch_all_does_not_shadow_an_anonymous_route() {
    let protected = route(1, "/api/{rest:*}", &[HttpMethod::Get], false);
    let anonymous = route(2, "/api/health", &[HttpMethod::Get], true);

    assert_eq!(
        RouteConflictGuard::check_pair(&protected, &anonymous),
        Ok(())
    );
}

#[test]
fn routes_of_different_hosts_never_conflict() {
    let first = on("a.example.com", 1, "/api/orders", &[HttpMethod::Get], false);
    let second = on("b.example.com", 2, "/api/orders", &[HttpMethod::Get], false);

    assert_eq!(RouteConflictGuard::check_pair(&first, &second), Ok(()));
}

#[test]
fn a_route_does_not_conflict_with_itself() {
    let route = route(1, "/api/orders", &[HttpMethod::Get], false);

    assert_eq!(RouteConflictGuard::check_pair(&route, &route), Ok(()));
}

#[test]
fn a_candidate_is_checked_against_the_stored_routes() {
    let stored = [
        route(1, "/api/health", &[HttpMethod::Get], false),
        route(2, "/api/orders", &[HttpMethod::Get], false),
    ];
    let clashing = route(3, "/api/orders", &[HttpMethod::Get], false);
    let free = route(4, "/api/orders", &[HttpMethod::Post], false);

    assert_eq!(
        RouteConflictGuard::check_candidate(&clashing, &stored),
        Err(same_pattern(3, 2))
    );
    assert_eq!(RouteConflictGuard::check_candidate(&free, &stored), Ok(()));
}

const PATTERNS: [&str; 6] = ["/a", "/a/{id}", "/a/{rest:*}", "/{id}", "/a/b", "/{rest:*}"];

fn pattern() -> impl Strategy<Value = &'static str> {
    (0..PATTERNS.len()).prop_map(|index| PATTERNS.get(index).copied().unwrap_or("/a"))
}

fn methods_of(pool: Vec<HttpMethod>) -> impl Strategy<Value = Vec<HttpMethod>> {
    let size = 1..=pool.len();
    subsequence(pool, size)
}

proptest! {
    #[test]
    fn the_conflict_rule_is_symmetric(
        first_pattern in pattern(),
        second_pattern in pattern(),
        first_methods in methods_of(vec![HttpMethod::Get, HttpMethod::Post, HttpMethod::Put]),
        second_methods in methods_of(vec![HttpMethod::Get, HttpMethod::Post, HttpMethod::Put]),
        first_anonymous in any::<bool>(),
        second_anonymous in any::<bool>(),
    ) {
        let first = route(1, first_pattern, &first_methods, first_anonymous);
        let second = route(2, second_pattern, &second_methods, second_anonymous);

        prop_assert_eq!(
            RouteConflictGuard::check_pair(&first, &second).is_err(),
            RouteConflictGuard::check_pair(&second, &first).is_err()
        );
    }

    #[test]
    fn disjoint_methods_never_conflict(
        first_pattern in pattern(),
        second_pattern in pattern(),
        first_methods in methods_of(vec![HttpMethod::Get, HttpMethod::Post]),
        second_methods in methods_of(vec![HttpMethod::Put, HttpMethod::Delete]),
        anonymous in prop_oneof![Just(false), Just(true)],
    ) {
        let first = route(1, first_pattern, &first_methods, anonymous);
        let second = route(2, second_pattern, &second_methods, anonymous);

        prop_assert_eq!(RouteConflictGuard::check_pair(&first, &second), Ok(()));
    }
}
