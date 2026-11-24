//! The refusals of IAM's REST operations through the production wiring over PostgreSQL: a refused
//! request leaves a rejected record that the writer appends, a thousand identical refusals are one
//! summarised record that no request waited for, and a request refused with 401 leaves none.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use iam_application::{
    FlushOutcome, RecordRejectedAttemptCommand, RecordRejectedAttemptCommandHandler,
    RejectedAttemptWriter,
};
use iam_domain::{
    AccessTokenVerifier, ActorRef, AuditAction, AuditReason, AuditTarget, RejectedAttemptLog,
    SecurityAuditLog,
};
use iam_infrastructure::JwtAccessTokenVerifier;
use service::bootstrap::{Adapters, router, token_repository};
use shared_domain::{Clock, CommandHandler as _, UuidGenerator};
use sqlx::PgPool;
use tower::ServiceExt as _;

use crate::authentication::config;
use crate::authentication::test_keys::{NOW, TestKey, USER_ID, user_claims};
use crate::support::database_url;

/// What the tests need of the application besides its router.
struct Wiring {
    app: Router,
    writer: RejectedAttemptWriter,
    log: Arc<dyn RejectedAttemptLog>,
    audit: Arc<dyn SecurityAuditLog>,
    clock: Arc<dyn Clock>,
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

/// The production wiring over the test database with the verifier on a clock fixed at [`NOW`].
async fn wiring(pool: &PgPool, name: &str, key: &TestKey) -> Wiring {
    let mut config = config(name, key);
    config.database.url = database_url(pool).await;
    let clock: Arc<dyn Clock> = Arc::new(test_support::clock::FixedClock::at(at(NOW)));
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
    let ids: Arc<dyn UuidGenerator> = Arc::clone(&adapters.uuid_generator);
    let writer = RejectedAttemptWriter::new(
        Arc::clone(&adapters.rejected_attempts),
        Arc::clone(&adapters.security_audit_log),
        Arc::clone(&adapters.clock),
        ids,
    );
    let (log, audit) = (
        Arc::clone(&adapters.rejected_attempts),
        Arc::clone(&adapters.security_audit_log),
    );
    let system_clock = Arc::clone(&adapters.clock);
    Wiring {
        app: router(adapters, &config).unwrap(),
        writer,
        log,
        audit,
        clock: system_clock,
    }
}

async fn post_roles(app: &Router, bearer: Option<&str>) -> StatusCode {
    let mut request = Request::post("/api/roles").header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = bearer {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let body = Body::from(r#"{"name":"Billing administrator"}"#);
    app.clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap()
        .status()
}

async fn rejected_records(pool: &PgPool) -> Vec<(String, String, Option<String>)> {
    sqlx::query_as(
        "SELECT action, reason, after_summary FROM iam_security_audit_events \
         WHERE outcome = 'rejected' ORDER BY seq",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_caller_without_the_key_is_refused_and_the_writer_appends_a_rejected_record(
    pool: PgPool,
) {
    let key = TestKey::generate();
    let wiring = wiring(&pool, "rejected-attempts-refused", &key).await;

    let status = post_roles(&wiring.app, Some(&key.sign(&user_claims()))).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(wiring.writer.flush().await, FlushOutcome::Appended(1));
    assert_eq!(
        rejected_records(&pool).await,
        vec![(
            "role.create".to_owned(),
            "forbidden".to_owned(),
            Some("attempts=1".to_owned())
        )]
    );
    let actor: String = sqlx::query_scalar("SELECT actor FROM iam_security_audit_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(actor, format!("user:{USER_ID}"));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_request_without_a_valid_token_is_401_and_leaves_no_record(pool: PgPool) {
    let key = TestKey::generate();
    let wiring = wiring(&pool, "rejected-attempts-unauthenticated", &key).await;

    let anonymous = post_roles(&wiring.app, None).await;
    let unknown = post_roles(&wiring.app, Some("not-a-jws")).await;

    assert_eq!(anonymous, StatusCode::UNAUTHORIZED);
    assert_eq!(unknown, StatusCode::UNAUTHORIZED);
    assert_eq!(wiring.writer.flush().await, FlushOutcome::Idle);
    assert_eq!(wiring.log.drain(at(NOW + 3600)).len(), 0);
    assert_eq!(rejected_records(&pool).await.len(), 0);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_thousand_identical_refusals_are_one_record_and_no_request_waits_for_the_chain_head(
    pool: PgPool,
) {
    let key = TestKey::generate();
    let wiring = wiring(&pool, "rejected-attempts-thousand", &key).await;
    let handler = RecordRejectedAttemptCommandHandler::new(
        Arc::clone(&wiring.log),
        Arc::clone(&wiring.clock),
    );
    let mut holder = pool.begin().await.unwrap();
    sqlx::query("SELECT seq FROM iam_security_audit_chain_head WHERE id = 1 FOR UPDATE")
        .fetch_one(&mut *holder)
        .await
        .unwrap();

    let offered = tokio::time::timeout(Duration::from_secs(5), async {
        for _ in 0..1000 {
            handler.handle(refusal()).await.unwrap();
        }
    })
    .await;

    assert!(offered.is_ok(), "an offer waited for the chain-head lock");
    holder.rollback().await.unwrap();
    assert_eq!(wiring.writer.flush().await, FlushOutcome::Appended(1));
    let records = rejected_records(&pool).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].2.as_deref(), Some("attempts=1000"));
    let head = wiring.audit.chain_head().await.unwrap();
    assert_eq!(head.seq(), 1);
}

fn refusal() -> RecordRejectedAttemptCommand {
    RecordRejectedAttemptCommand {
        actor: ActorRef::User(shared_domain::Uuid::parse(USER_ID).unwrap()),
        action: AuditAction::new("role.create").unwrap(),
        reason: AuditReason::new("forbidden").unwrap(),
        target: AuditTarget::new("operation", "role.create").unwrap(),
        request_id: None,
    }
}
