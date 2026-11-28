//! The steps of the stream scenarios: a streaming gateway in process, its subjects and the
//! WebSocket and event streams they open.

use cucumber::{given, then, when};

use crate::gateway_streams::StreamsPlan;
use crate::world::AppWorld;

#[given("a streaming gateway with a WebSocket route and an SSE route")]
fn streaming_gateway(world: &mut AppWorld) {
    world.streams_plan = Some(StreamsPlan::default());
}

#[given(expr = "the streaming subject {string} holds the stream keys without expiry")]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn subject_holds_keys(world: &mut AppWorld, name: String) {
    plan(world).assign(&name, None);
}

#[given(
    expr = "the streaming subject {string} holds the stream keys through an assignment that expires in {int} seconds"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn subject_holds_keys_until(world: &mut AppWorld, name: String, seconds: u64) {
    plan(world).assign(&name, Some(seconds));
}

#[given(
    expr = "the streaming subject {string} also holds the stream keys through an assignment that never expires"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn subject_also_holds_keys(world: &mut AppWorld, name: String) {
    plan(world).assign(&name, None);
}

#[given(expr = "the streaming subject {string} holds no stream key")]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn subject_holds_no_key(world: &mut AppWorld, name: String) {
    plan(world).without_key(&name);
}

fn plan(world: &mut AppWorld) -> &mut StreamsPlan {
    world
        .streams_plan
        .as_mut()
        .expect("a streaming gateway was described")
}

#[when(expr = "the streaming subject {string} opens a WebSocket")]
async fn subject_opens_websocket(world: &mut AppWorld, name: String) {
    world.started_streams().await.open(Some(&name), "ws").await;
}

#[when(expr = "the streaming subject {string} opens an event stream")]
async fn subject_opens_events(world: &mut AppWorld, name: String) {
    world
        .started_streams()
        .await
        .open(Some(&name), "events")
        .await;
}

#[when("a request without a token opens a WebSocket")]
async fn anonymous_opens_websocket(world: &mut AppWorld) {
    world.started_streams().await.open(None, "ws").await;
}

#[when(expr = "the stream keys of the streaming subject {string} are revoked")]
async fn keys_revoked(world: &mut AppWorld, name: String) {
    world.started_streams().await.revoke_keys(&name).await;
}

#[when(expr = "{int} seconds pass on the gateway clock")]
async fn seconds_pass(world: &mut AppWorld, seconds: u64) {
    world.started_streams().await.pass(seconds);
}

#[when("the proof of the gateway ages past the hard bound")]
async fn proof_ages(world: &mut AppWorld) {
    world.started_streams().await.age_proof();
}

#[then(expr = "the opening answer status of the WebSocket of {string} should be {int}")]
async fn websocket_status(world: &mut AppWorld, name: String, status: u16) {
    let gateway = world.started_streams().await;
    assert_eq!(gateway.answer(Some(&name), "ws"), status);
}

#[then(expr = "the opening answer status of the event stream of {string} should be {int}")]
async fn events_status(world: &mut AppWorld, name: String, status: u16) {
    let gateway = world.started_streams().await;
    assert_eq!(gateway.answer(Some(&name), "events"), status);
}

#[then(expr = "the opening answer status of the WebSocket without a token should be {int}")]
async fn anonymous_status(world: &mut AppWorld, status: u16) {
    let gateway = world.started_streams().await;
    assert_eq!(gateway.answer(None, "ws"), status);
}

#[then(expr = "a frame sent over the WebSocket of {string} should come back unchanged")]
async fn frame_comes_back(world: &mut AppWorld, name: String) {
    world
        .started_streams()
        .await
        .echo(&name, b"\x81\x05hello")
        .await;
}

#[then(expr = "the event stream of {string} should deliver its first event")]
async fn first_event(world: &mut AppWorld, name: String) {
    world.started_streams().await.first_event(&name).await;
}

#[then(expr = "the stream registry should hold {int} stream(s) of the subject {string}")]
async fn registry_holds(world: &mut AppWorld, expected: usize, name: String) {
    let gateway = world.started_streams().await;
    assert_eq!(gateway.held_by(&name), expected);
}

#[then(expr = "the WebSocket of {string} should be closed with code {int}")]
async fn websocket_closed(world: &mut AppWorld, name: String, code: u16) {
    world
        .started_streams()
        .await
        .expect_closed(&name, code)
        .await;
}

#[then(expr = "the event stream of {string} should end")]
async fn events_end(world: &mut AppWorld, name: String) {
    world.started_streams().await.expect_ended(&name).await;
}

#[then("the re-evaluation of the revoked version should have finished")]
async fn reevaluation_finished(world: &mut AppWorld) {
    assert!(world.started_streams().await.reevaluated());
}

#[then(expr = "the streams upstream should have received {int} request(s)")]
async fn upstream_received(world: &mut AppWorld, expected: usize) {
    let gateway = world.started_streams().await;
    assert_eq!(gateway.upstream_requests(), expected);
}
