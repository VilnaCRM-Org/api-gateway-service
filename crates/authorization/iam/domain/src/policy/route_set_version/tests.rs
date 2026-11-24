use super::RouteSetVersion;
use crate::route::RouteParts;
use crate::route::fixtures::{fields, parts};
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::http_method::HttpMethod;

fn route(number: u32, path: &str) -> RouteParts {
    parts(number, fields("api.example.com", path, &[HttpMethod::Get]))
}

#[test]
fn the_version_does_not_depend_on_the_order() {
    let first = route(1, "/a");
    let second = route(2, "/b");

    assert_eq!(
        RouteSetVersion::of(&[first.clone(), second.clone()]),
        RouteSetVersion::of(&[second, first])
    );
}

#[test]
fn the_version_changes_with_the_routes_and_their_versions() {
    let first = route(1, "/a");
    let mut bumped = first.clone();
    bumped.version = EntityVersion::new(4).unwrap();

    let versions = [
        RouteSetVersion::of(&[]),
        RouteSetVersion::of(std::slice::from_ref(&first)),
        RouteSetVersion::of(&[bumped]),
        RouteSetVersion::of(&[first, route(2, "/b")]),
    ];

    for (index, version) in versions.iter().enumerate() {
        assert!(version.value() >= 1);
        assert!(version.value() < (1_i64 << 52));
        for other in versions.iter().skip(index + 1) {
            assert_ne!(version, other);
        }
    }
}
