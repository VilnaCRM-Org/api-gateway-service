//! The steps of the IAM context.

use std::time::Duration;

use axum::http::header::WWW_AUTHENTICATE;
use cucumber::{given, then};
use serde_json::{Value, json};
use test_support::policy_epoch::seeded_policy_epoch;

use crate::tokens::{SigningKey, USER_ID};
use crate::world::AppWorld;

/// How often the step reads the policy epoch while the relay of the scenario takes its lease.
const RELAY_POLL: Duration = Duration::from_millis(100);

/// How many times the step reads before it gives up on the lease of the relay.
const RELAY_POLLS: u32 = 50;

#[then("the IAM policy epoch should be the one of the startup registration")]
async fn policy_epoch_should_be_the_one_of_the_startup_registration(world: &mut AppWorld) {
    let seeded = seeded_policy_epoch();
    // The outbox relay of the scenario runs as in `service serve` (Story 7.6) and fences the epoch
    // once when it takes its lease (Story 7.4), so the relay epoch is the next one after the seed.
    let fenced = seeded.relay_epoch().value().checked_add(1).unwrap();
    let mut epoch = world.policy_epoch().await;
    for _ in 0..RELAY_POLLS {
        if epoch.relay_epoch().value() == fenced {
            break;
        }
        tokio::time::sleep(RELAY_POLL).await;
        epoch = world.policy_epoch().await;
    }
    // The activations of IAM's own OpenAPI and GraphQL specifications each take a policy version
    // and change the catalogue, and their state rows move the digest to the one of the newest
    // `__head` row; nothing else moves from the seeded epoch.
    assert_eq!(epoch.version().value(), 2);
    assert_eq!(epoch.catalog_epoch(), 2);
    assert_ne!(epoch.digest(), seeded.digest());
    assert_eq!(
        epoch.digest().as_bytes().to_vec(),
        world.latest_head_digest().await
    );
    assert_eq!(epoch.log_epoch(), seeded.log_epoch());
    assert_eq!(epoch.relay_epoch().value(), fenced);
}

#[given("a caller authenticated as the bootstrapped administrator")]
fn caller_as_the_administrator(world: &mut AppWorld) {
    world.authenticate_as_administrator();
}

#[given("a caller authenticated with a valid service token that holds no IAM key")]
fn caller_without_iam_keys(world: &mut AppWorld) {
    world.authenticate_as_unprivileged_service();
}

#[given("a caller presenting a token signed by an unknown key")]
fn caller_with_an_unknown_key(world: &mut AppWorld) {
    world.authenticate_with_unknown_key();
}

#[given(expr = "a subject token of a user in session {string}")]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn subject_token_of_a_user(world: &mut AppWorld, session: String) {
    let token = world.signing_key().user_token(&session);
    world.set_subject_token(token);
}

#[given(expr = "an expired subject token of a user in session {string}")]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn expired_subject_token_of_a_user(world: &mut AppWorld, session: String) {
    let token = world.signing_key().expired_user_token(&session);
    world.set_subject_token(token);
}

#[given("a subject token signed by an unknown key")]
fn subject_token_from_an_unknown_key(world: &mut AppWorld) {
    let token = SigningKey::generate().user_token("session-unknown");
    world.set_subject_token(token);
}

#[given("an empty subject token")]
fn empty_subject_token(world: &mut AppWorld) {
    world.set_subject_token(String::new());
}

#[given(expr = "the session {string} is revoked")]
async fn session_is_revoked(world: &mut AppWorld, session: String) {
    world.revoke_session(&session).await;
}

/// The last two replies: the REST answer and the GraphQL answer, as bare resolution objects.
fn resolutions(world: &AppWorld) -> [Value; 2] {
    let [.., rest, graphql] = world.history() else {
        panic!("the scenario sent fewer than two requests");
    };
    let from_graphql = graphql
        .json()
        .pointer("/data/resolveToken")
        .cloned()
        .unwrap_or(Value::Null);
    [rest.json(), from_graphql]
}

#[then("the REST and GraphQL token resolutions should be the same")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
fn resolutions_should_be_the_same(world: &mut AppWorld) {
    let [rest, graphql] = resolutions(world);
    assert!(rest.is_object(), "REST body: {rest}");
    // GraphQL answers every field of the selection; REST leaves out the absent ones.
    let present: Value = graphql
        .as_object()
        .map(|fields| {
            fields
                .iter()
                .filter(|(_name, value)| !value.is_null())
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect()
        })
        .map_or(Value::Null, Value::Object);
    assert_eq!(rest, present);
}

#[then(
    expr = "both token resolutions should be resolved for a {string} subject in session {string}"
)]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn resolutions_should_be_resolved(world: &mut AppWorld, kind: String, session: String) {
    for resolution in resolutions(world) {
        assert_eq!(resolution["resolved"], true, "{resolution}");
        assert_eq!(resolution["subjectId"], USER_ID, "{resolution}");
        assert_eq!(resolution["subjectKind"], kind.as_str(), "{resolution}");
        assert_eq!(resolution["sessionId"], session.as_str(), "{resolution}");
        assert_eq!(resolution["roles"], json!(["ROLE_USER"]), "{resolution}");
        assert!(resolution["expiresAt"].is_i64(), "{resolution}");
    }
}

#[then(expr = "both token resolutions should be unresolved with reason {string}")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn resolutions_should_be_unresolved(world: &mut AppWorld, reason: String) {
    for resolution in resolutions(world) {
        assert_eq!(resolution["resolved"], false, "{resolution}");
        assert_eq!(resolution["reason"], reason.as_str(), "{resolution}");
        assert!(resolution["subjectId"].is_null(), "{resolution}");
    }
}

#[then("no response should contain the subject token")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
fn no_response_echoes_the_token(world: &mut AppWorld) {
    let token = world.subject_token().expect("the scenario has no token");
    assert!(!token.is_empty(), "the scenario has an empty token");
    for reply in world.history() {
        assert!(!reply.body.contains(token), "echoed: {}", reply.body);
    }
}

#[then("the response should challenge with the Bearer scheme")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
fn response_challenges_with_bearer(world: &mut AppWorld) {
    let challenge = world
        .reply()
        .headers
        .get(WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok());
    assert_eq!(challenge, Some("Bearer"));
}

#[then(expr = "the GraphQL error code should be {string}")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "cucumber fixes the step signature"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "cucumber fixes the step signature"
)]
fn graphql_error_code(world: &mut AppWorld, code: String) {
    let json = world.reply().json();
    assert_eq!(
        json.pointer("/errors/0/extensions/code")
            .and_then(Value::as_str),
        Some(code.as_str()),
        "body: {}",
        world.reply().body
    );
}
