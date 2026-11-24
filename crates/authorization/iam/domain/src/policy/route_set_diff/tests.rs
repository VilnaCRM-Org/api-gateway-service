use super::RouteSetDiff;
use crate::policy::route_revocation_rule::RouteChangeClass;
use crate::route::RouteParts;
use crate::route::fields::{RouteDraft, RouteFields};
use crate::route::fixtures::{draft, fields, parts};
use crate::route::settings::{EnforcementMode, RouteFlag, RouteFlags};
use crate::value_object::http_method::HttpMethod;

const HOST: &str = "api.example.com";

fn stored(number: u32, path: &str) -> RouteParts {
    parts(number, fields(HOST, path, &[HttpMethod::Get]))
}

fn declared(path: &str) -> RouteFields {
    fields(HOST, path, &[HttpMethod::Get])
}

fn with(path: &str, change: impl FnOnce(&mut RouteDraft)) -> RouteFields {
    let mut route = draft(HOST, path, &[HttpMethod::Get]);
    change(&mut route);
    RouteFields::new(&route).unwrap()
}

#[test]
fn a_set_adds_changes_and_removes_routes_by_methods_and_pattern() {
    let current = [stored(1, "/a"), stored(2, "/b")];
    let slower = with("/b", |route| route.request_timeout_ms = 5_000);

    let diff = RouteSetDiff::between(&current, vec![slower.clone(), declared("/c")]);

    assert_eq!(diff.added(), [declared("/c")]);
    assert_eq!(diff.changed().len(), 1);
    assert_eq!(diff.changed()[0].before, current[1]);
    assert_eq!(diff.changed()[0].after, slower);
    assert_eq!(diff.changed()[0].changed_fields(), ["timeouts"]);
    assert_eq!(diff.removed(), [current[0].clone()]);
    assert_eq!(diff.unchanged(), 0);
    assert!(!diff.is_empty());
    assert_eq!(diff.class(), RouteChangeClass::Revocation);
}

#[test]
fn the_same_set_changes_nothing() {
    let current = [stored(1, "/a"), stored(2, "/b")];

    let diff = RouteSetDiff::between(&current, vec![declared("/b"), declared("/a")]);

    assert!(diff.is_empty());
    assert_eq!(diff.unchanged(), 2);
    assert_eq!(diff.class(), RouteChangeClass::Standard);
}

#[test]
fn routes_with_other_methods_are_other_routes() {
    let current = [stored(1, "/a")];
    let post = fields(HOST, "/a", &[HttpMethod::Post]);

    let diff = RouteSetDiff::between(&current, vec![post.clone()]);

    assert_eq!(diff.added(), [post]);
    assert_eq!(diff.removed(), [current[0].clone()]);
}

#[test]
fn a_route_declared_twice_is_added_twice() {
    let diff = RouteSetDiff::between(&[], vec![declared("/a"), declared("/a")]);

    assert_eq!(diff.added().len(), 2);
}

#[test]
fn only_adding_a_route_or_changing_a_timeout_is_standard() {
    let current = [stored(1, "/a")];
    let slower = with("/a", |route| route.request_timeout_ms = 5_000);

    let diff = RouteSetDiff::between(&current, vec![slower, declared("/new")]);

    assert_eq!(diff.class(), RouteChangeClass::Standard);
}

#[test]
fn clearing_anonymous_is_a_revocation() {
    let open = with("/a", |route| {
        route.flags = RouteFlags::default().with(RouteFlag::Anonymous, true);
    });
    let current = [parts(1, open)];

    let diff = RouteSetDiff::between(&current, vec![declared("/a")]);

    assert_eq!(diff.class(), RouteChangeClass::Revocation);
}

#[test]
fn moving_audit_to_enforce_is_a_revocation() {
    let auditing = with("/a", |route| route.enforcement = EnforcementMode::Audit);
    let current = [parts(1, auditing)];

    let diff = RouteSetDiff::between(&current, vec![declared("/a")]);

    assert_eq!(diff.class(), RouteChangeClass::Revocation);
}

#[test]
fn deleting_a_route_is_a_revocation() {
    let current = [stored(1, "/a")];

    let diff = RouteSetDiff::between(&current, Vec::new());

    assert_eq!(diff.removed().len(), 1);
    assert_eq!(diff.class(), RouteChangeClass::Revocation);
}
