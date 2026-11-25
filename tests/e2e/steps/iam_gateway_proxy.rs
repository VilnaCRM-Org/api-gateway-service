//! The steps of the gateway proxy scenarios: a route and its subjects in an in-process gateway
//! that forwards to a fake upstream, and the number of requests that upstream received.

use cucumber::{given, then, when};

use crate::gateway_proxy::GatewayPlan;
use crate::world::AppWorld;

/// Splits `"GET /api/users/{id}"` into the method and the path pattern.
fn split_route(route: &str) -> (&str, &str) {
    route
        .split_once(' ')
        .expect("a route is written as `METHOD /path`")
}

#[given(
    expr = "a gateway route {string} of the host {string} for the service {string} guarded by the key {string}"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn gateway_route(world: &mut AppWorld, route: String, host: String, service: String, key: String) {
    let (method, pattern) = split_route(&route);
    world.gateway_plan = Some(GatewayPlan::route(&host, &service, method, pattern, &key));
}

#[given(expr = "the gateway route allows the origin {string} with credentials")]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn route_allows_origin(world: &mut AppWorld, origin: String) {
    world
        .gateway_plan
        .as_mut()
        .expect("a gateway route was described")
        .allow_origin(&origin);
}

#[given(expr = "the gateway subject {string} holds the key {string}")]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn subject_holds_key(world: &mut AppWorld, name: String, key: String) {
    world
        .gateway_plan
        .as_mut()
        .expect("a gateway route was described")
        .grant(&name, &key);
}

#[given(expr = "the gateway subject {string} holds no key")]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn subject_holds_no_key(world: &mut AppWorld, name: String) {
    world
        .gateway_plan
        .as_mut()
        .expect("a gateway route was described")
        .without_key(&name);
}

#[when(expr = "the gateway subject {string} sends {word} request to {string} through the gateway")]
async fn subject_sends(world: &mut AppWorld, name: String, method: String, path: String) {
    world.send_through_gateway(&name, &method, &path).await;
}

#[when(
    expr = "the gateway subject {string} sends {word} request to {string} through the gateway from the origin {string} with the session cookie"
)]
async fn subject_sends_from_browser(
    world: &mut AppWorld,
    name: String,
    method: String,
    path: String,
    origin: String,
) {
    world
        .send_through_gateway_from_browser(&name, &method, &path, &origin)
        .await;
}

#[then(expr = "the fake upstream should have received {int} request(s)")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
fn upstream_received(world: &mut AppWorld, expected: usize) {
    let gateway = world.gateway.as_ref().expect("the gateway was started");
    assert_eq!(gateway.upstream_requests(), expected);
}
