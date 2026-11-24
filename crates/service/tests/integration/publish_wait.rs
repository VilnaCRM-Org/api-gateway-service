//! A write waits for the relay's stored offset of its policy version through the production
//! wiring over PostgreSQL (Story 7.6): with the relay stopped an assignment, which affects
//! decisions, returns `202` once `PUBLISH_WAIT_TIMEOUT` passes on the controlled clock, a replay
//! carries the stored outcome and waits for nothing, and a write that does not affect decisions
//! (creating a role without grants, editing its description) does not wait at all. The caller is
//! bootstrapped as the administrator first, so the authorization of the operations (Story 6.11)
//! lets its writes through.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use http_body_util::BodyExt as _;
use iam_application::PublishingUnitOfWork;
use iam_domain::{AccessTokenVerifier, IamUnitOfWork, ServiceName, SubjectRef};
use iam_infrastructure::{JwtAccessTokenVerifier, PgPropagationStore};
use serde_json::Value;
use service::bootstrap::{Adapters, bootstrap_administrator, router, token_repository};
use shared_domain::Clock;
use sqlx::PgPool;
use test_support::clock::{FixedClock, ManualClock};
use tokio::task::JoinHandle;
use tower::ServiceExt as _;

use crate::authentication::config;
use crate::authentication::test_keys::{NOW, TestKey, service_claims};
use crate::support::database_url;

/// How long the writes of these tests wait for the acknowledgement on the controlled clock.
const WAIT: Duration = Duration::from_secs(5);

/// The service principal of [`service_claims`], bootstrapped as the administrator.
const CALLER: &str = "user-service";

/// Counts the roles the tests create, leaving out the administrator role of the bootstrap.
const CREATED_ROLES: &str = "SELECT count(*) FROM iam_roles WHERE name = 'Billing administrator'";

/// Counts the active assignments to users, leaving out the administrator's (a service principal).
const CREATED_ASSIGNMENTS: &str =
    "SELECT count(*) FROM iam_user_roles WHERE subject_kind = 'user' AND revoked_at IS NULL";

/// The user that the tests assign the created role to.
const ASSIGNEE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";

/// How long a request that must not wait gets before the test fails.
const NO_WAIT: Duration = Duration::from_secs(10);

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

/// The application over the test database whose writes wait on `wait_clock`, with [`CALLER`] as
/// its administrator; the relay does not run.
async fn app(pool: &PgPool, name: &str, key: &TestKey, wait_clock: &Arc<ManualClock>) -> Router {
    let mut config = config(name, key);
    config.database.url = database_url(pool).await;
    let clock: Arc<dyn Clock> = Arc::new(FixedClock::at(at(NOW)));
    let verifier: Arc<dyn AccessTokenVerifier> = Arc::new(
        JwtAccessTokenVerifier::from_file(
            &config.tokens.public_keys_file,
            &config.tokens.jwt,
            Arc::clone(&clock),
        )
        .unwrap(),
    );
    let mut adapters = Adapters::connect(&config).await.unwrap();
    adapters.tokens = token_repository(&config, verifier, &clock, pool);
    bootstrap_administrator(
        &adapters,
        SubjectRef::service(ServiceName::new(CALLER).unwrap()),
    )
    .await
    .unwrap();
    let concrete = Arc::clone(wait_clock);
    let waiting: Arc<dyn Clock> = concrete;
    let inner: Arc<dyn IamUnitOfWork> = Arc::clone(&adapters.unit_of_work);
    adapters.write_unit_of_work = Arc::new(PublishingUnitOfWork::new(
        inner,
        Arc::new(PgPropagationStore::new(pool.clone())),
        waiting,
        WAIT,
    ));
    router(adapters, &config).unwrap()
}

/// Moves the controlled clock past the wait until the returned task is aborted.
fn tick(clock: &Arc<ManualClock>) -> JoinHandle<()> {
    let clock = Arc::clone(clock);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(50)).await;
            clock.advance(WAIT);
        }
    })
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

async fn send(
    app: &Router,
    (method, path): (Method, &str),
    token: &str,
    extra: &[(&str, &str)],
    body: &str,
) -> Reply {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    for (name, value) in extra {
        request = request.header(*name, *value);
    }
    let response = tokio::time::timeout(
        NO_WAIT,
        app.clone()
            .oneshot(request.body(Body::from(body.to_owned())).unwrap()),
    )
    .await
    .expect("the request waited for an acknowledgement that cannot come")
    .unwrap();
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    Reply {
        status: parts.status,
        headers: parts.headers,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    }
}

/// Creates a role without grants, a write that does not wait, and returns its id.
async fn create_role(app: &Router, token: &str) -> String {
    let created = send(
        app,
        (Method::POST, "/api/roles"),
        token,
        &[],
        r#"{"name":"Billing administrator"}"#,
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED);
    created.body["id"].as_str().unwrap().to_owned()
}

/// The body of a global assignment of `role` to [`ASSIGNEE`].
fn assignment_of(role: &str) -> String {
    serde_json::json!({
        "subject": {"kind": "user", "id": ASSIGNEE},
        "roleId": role,
        "scope": {"kind": "global"},
    })
    .to_string()
}

fn header_text<'a>(reply: &'a Reply, name: &str) -> Option<&'a str> {
    reply
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
}

async fn count(pool: &PgPool, statement: &'static str) -> i64 {
    sqlx::query_scalar(statement).fetch_one(pool).await.unwrap()
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_write_with_the_relay_stopped_is_202_and_its_change_and_audit_record_are_committed(
    pool: PgPool,
) {
    let key = TestKey::generate();
    let clock = Arc::new(ManualClock::at(at(NOW)));
    let app = app(&pool, "publish-wait-pending", &key, &clock).await;
    let token = key.sign(&service_claims());
    let role = create_role(&app, &token).await;
    let ticker = tick(&clock);

    let reply = send(
        &app,
        (Method::POST, "/api/user-roles"),
        &token,
        &[],
        &assignment_of(&role),
    )
    .await;

    ticker.abort();
    assert_eq!(reply.status, StatusCode::ACCEPTED);
    assert_eq!(
        header_text(&reply, "iam-propagation-status"),
        Some("committed_pending_propagation")
    );
    assert!(header_text(&reply, "iam-policy-version").is_some());
    assert!(header_text(&reply, "iam-policy-offset").is_none());
    assert_eq!(reply.body["roleId"], role.as_str());
    assert_eq!(count(&pool, CREATED_ASSIGNMENTS).await, 1);
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM iam_security_audit_events \
             WHERE outcome = 'committed' AND action = 'user_role.assign'"
        )
        .await,
        1
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_replay_carries_the_stored_propagation_outcome_and_waits_for_nothing(pool: PgPool) {
    let key = TestKey::generate();
    let clock = Arc::new(ManualClock::at(at(NOW)));
    let app = app(&pool, "publish-wait-replay", &key, &clock).await;
    let token = key.sign(&service_claims());
    let role = create_role(&app, &token).await;
    let body = assignment_of(&role);
    let extra = [("idempotency-key", "publish-wait-replay-key")];
    let ticker = tick(&clock);
    let first = send(
        &app,
        (Method::POST, "/api/user-roles"),
        &token,
        &extra,
        &body,
    )
    .await;
    ticker.abort();

    let replay = send(
        &app,
        (Method::POST, "/api/user-roles"),
        &token,
        &extra,
        &body,
    )
    .await;

    assert_eq!(first.status, StatusCode::ACCEPTED);
    assert_eq!(replay.status, StatusCode::ACCEPTED);
    assert_eq!(
        header_text(&replay, "iam-policy-version"),
        header_text(&first, "iam-policy-version")
    );
    assert_eq!(
        header_text(&replay, "iam-propagation-status"),
        Some("committed_pending_propagation")
    );
    assert_eq!(count(&pool, CREATED_ASSIGNMENTS).await, 1);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_write_that_does_not_affect_decisions_carries_no_offset_and_does_not_wait(pool: PgPool) {
    let key = TestKey::generate();
    let clock = Arc::new(ManualClock::at(at(NOW)));
    let app = app(&pool, "publish-wait-unaffected", &key, &clock).await;
    let token = key.sign(&service_claims());
    let created = send(
        &app,
        (Method::POST, "/api/roles"),
        &token,
        &[],
        r#"{"name":"Billing administrator"}"#,
    )
    .await;
    let id = created.body["id"].as_str().unwrap().to_owned();

    let renamed = send(
        &app,
        (Method::PATCH, format!("/api/roles/{id}").as_str()),
        &token,
        &[("if-match", "\"1\"")],
        r#"{"description":"Manages invoices."}"#,
    )
    .await;

    for reply in [&created, &renamed] {
        assert!(header_text(reply, "iam-policy-offset").is_none());
        assert!(header_text(reply, "iam-policy-version").is_none());
        assert!(header_text(reply, "iam-propagation-status").is_none());
    }
    assert_eq!(created.status, StatusCode::CREATED);
    assert_eq!(renamed.status, StatusCode::OK);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_request_for_the_propagated_mode_is_refused_with_422_naming_the_mode(pool: PgPool) {
    let key = TestKey::generate();
    let clock = Arc::new(ManualClock::at(at(NOW)));
    let app = app(&pool, "publish-wait-propagated", &key, &clock).await;
    let token = key.sign(&service_claims());

    let reply = send(
        &app,
        (Method::POST, "/api/roles"),
        &token,
        &[("prefer", "wait=propagated")],
        r#"{"name":"Billing administrator"}"#,
    )
    .await;

    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(reply.body.to_string().contains("propagated"));
    assert_eq!(count(&pool, CREATED_ROLES).await, 0);
}
