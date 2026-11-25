//! The access log of the gateway (Story 14.1, FR-50, NFR-20, NFR-24) in process: a real
//! [`Pipeline`] with its access record step, the production writer thread and a recording sink.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Body;
use axum::http::header::{AUTHORIZATION, COOKIE};
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse as _, Response};
use iam_application::{
    AccessFacts, AccessLogCounters, AccessRecordBuilder, AccessRecorder, DecisionTrace,
    FreshnessState, RequestAuthorizer, RequestFacts, ResponseFacts, RouteFacts, VerdictFacts,
    access_log_channel,
};
use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{
    AccessClass, AccessDecision, AccessEntry, AccessLane, AccessToken, AccessTokenParts,
    AccessTokenVerifier, AssignmentScope, AssignmentState, BootClock as _, BootInstant,
    CatalogueEntryState, ClassBudgets, CompiledRoleSet, DecisionReason, EnforcementMode,
    ForwardError, FreshnessRule, GrantStatus, HttpMethod, PermissionGrant, PolicyVersion,
    PolicyView, RevocationView, Rng as _, RoleId, RouteState, SampleRate, ServiceName, SessionId,
    SubjectId, SubjectKind, SubjectRef, TokenId, TokenMemo, TokenRejection, TokenRepository,
    UpstreamForwarder, UpstreamState, UpstreamTarget,
};
use iam_infrastructure::{
    CachingTokenRepository, MokaTokenMemo, SnapshotRevocationView, TokenMemoSettings, render_entry,
};
use service::bootstrap::gateway::access_log::AccessLogAdapters;
use service::bootstrap::gateway::pipeline::{Pipeline, UnauditedCommands, router};
use service::config::AccessLogSettings;
use shared_domain::{Clock, CommandBus, Uuid};
use test_support::access_log_sink::RecordingAccessLogSink;
use test_support::access_token::FakeAccessTokenVerifier;
use test_support::boot_clock::FakeBootClock;
use test_support::clock::FixedClock;
use test_support::gateway_snapshot::GatewaySnapshot;
use test_support::id::SequenceUuidGenerator;
use test_support::log::LogRecorder;
use test_support::rng::FakeRng;
use test_support::route::{route, route_draft};
use test_support::seed::TestRng;
use test_support::upstream::upstream;
use tokio::time::Instant;
use tower::ServiceExt as _;

pub(crate) const HOST: &str = "api.example.test";
const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";
const OTHER_USER: &str = "7a1c5e3b-2d4f-4a6b-8c9d-0e1f2a3b4c5d";
const ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890cd";
pub(crate) const NOW: u64 = 1_800_000_000;
pub(crate) const GOOD: &str = "good.token.value";
pub(crate) const OTHER: &str = "other.token.value";

pub(crate) fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

/// A token of `user` that is valid at `now` seconds after the epoch.
fn token(user: &str, session: &str, now: u64) -> AccessToken {
    AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(Uuid::parse(user).unwrap()),
        session: Some(SessionId::new(session).unwrap()),
        token_id: TokenId::new("token-1").unwrap(),
        roles: vec!["ROLE_USER".to_owned()],
        issued_at: at(now.saturating_sub(60)),
        expires_at: at(now.saturating_add(900)),
    })
}

/// A catalogue entry; `flags` are `(sensitive, audit_always)`.
fn entry(key: &str, flags: (bool, bool)) -> CatalogueEntryState {
    let (sensitive, audit_always) = flags;
    CatalogueEntryState {
        key: key.to_owned(),
        sensitive,
        audit_always,
    }
}

/// The snapshot: four services, each with one `GET` route. `users` is an ordinary operation,
/// `audit` is always audited, `secret` is sensitive and `wild` is held by `USER` through the
/// wildcard `rest:wild:*`. `USER` holds the others exactly; `OTHER_USER` holds nothing.
fn snapshot(rng: &mut TestRng) -> GatewaySnapshot {
    let backend = UpstreamState::of(upstream(rng, "backend", "backend").parts());
    let backend_id = backend.id;
    let role = RoleId::parse(ROLE).unwrap();
    let grants = CompiledRoleSet::compile(
        [
            "rest:users:GET /api/users/{}",
            "rest:audit:GET /api/audit-me",
            "rest:secret:GET /api/secret",
            "rest:wild:*",
        ]
        .into_iter()
        .map(|raw| (PermissionGrant::parse(raw).unwrap(), GrantStatus::Active)),
    );
    let mut snapshot = GatewaySnapshot::at(PolicyVersion::new(7).unwrap())
        .with_assignments(
            SubjectRef::user(Uuid::parse(USER).unwrap()),
            vec![AssignmentState {
                role,
                scope: AssignmentScope::Global,
                expires_at_micros: None,
            }],
        )
        .with_role_set(role, grants)
        .with_upstream(backend);
    let services = [
        (
            "users",
            "/api/users/{id}",
            "rest:users:GET /api/users/{}",
            false,
            false,
        ),
        (
            "audit",
            "/api/audit-me",
            "rest:audit:GET /api/audit-me",
            false,
            true,
        ),
        (
            "secret",
            "/api/secret",
            "rest:secret:GET /api/secret",
            true,
            false,
        ),
        (
            "wild",
            "/api/wild/{id}",
            "rest:wild:GET /api/wild/{}",
            false,
            false,
        ),
    ];
    for (service, template, key, sensitive, audit_always) in services {
        let draft = route_draft(HOST, template, &[HttpMethod::Get], service, backend_id);
        snapshot = snapshot
            .with_route(RouteState::of(route(rng, &draft).parts()))
            .with_catalogue(
                ServiceName::new(service).unwrap(),
                vec![entry(key, (sensitive, audit_always))],
            );
    }
    for (service, template, key, enforcement) in [
        (
            "auditmode",
            "/api/audit-mode/{id}",
            "rest:auditmode:GET /api/audit-mode/{}",
            EnforcementMode::Audit,
        ),
        (
            "enforcemode",
            "/api/enforce-mode/{id}",
            "rest:enforcemode:GET /api/enforce-mode/{}",
            EnforcementMode::Enforce,
        ),
    ] {
        let mut draft = route_draft(HOST, template, &[HttpMethod::Get], service, backend_id);
        draft.enforcement = enforcement;
        snapshot = snapshot
            .with_route(RouteState::of(route(rng, &draft).parts()))
            .with_catalogue(
                ServiceName::new(service).unwrap(),
                vec![entry(key, (false, false))],
            );
    }
    snapshot
}

/// A forwarder that answers 200 to everything it receives.
#[derive(Debug)]
struct Ok200;

#[async_trait::async_trait]
impl UpstreamForwarder for Ok200 {
    type Request = Request<Body>;
    type Response = Response;

    async fn forward(
        &self,
        _target: UpstreamTarget,
        _request: Request<Body>,
    ) -> Result<Response, ForwardError> {
        Ok(StatusCode::OK.into_response())
    }
}

struct Harness {
    router: Router,
    sink: Arc<RecordingAccessLogSink>,
    access: AccessLogAdapters,
}

fn harness(rate: SampleRate, seed: u64) -> Harness {
    let clock: Arc<dyn Clock> = Arc::new(FixedClock::at(at(NOW)));
    let sink = Arc::new(RecordingAccessLogSink::new());
    let access = AccessLogAdapters::start(
        &AccessLogSettings {
            allow_sample_rate: rate,
            class_budgets: ClassBudgets::default(),
            channel_capacity: 65_536,
        },
        Arc::new(FakeRng::seeded(seed)),
        Arc::clone(&clock),
        Arc::<RecordingAccessLogSink>::clone(&sink),
    )
    .unwrap();
    let router = pipeline_router(&clock, &access);
    Harness {
        router,
        sink,
        access,
    }
}

/// The public pipeline of the snapshot above, deciding on `clock` and recording through `access`,
/// whose audit gate it is under (audit-or-deny).
pub(crate) fn pipeline_router(clock: &Arc<dyn Clock>, access: &AccessLogAdapters) -> Router {
    let mut rng = TestRng::from_env();
    let view = Arc::new(test_support::gateway_snapshot::CountingPolicyView::serving(
        snapshot(&mut rng),
    ));
    let boot = Arc::new(FakeBootClock::starting_at(BootInstant::from_elapsed(
        Duration::from_secs(100),
    )));
    let freshness = Arc::new(FreshnessState::new(
        FreshnessRule::new(Duration::from_secs(15), Duration::from_secs(2)),
        Arc::<FakeBootClock>::clone(&boot),
    ));
    freshness.attach(
        FreshnessProof {
            taken_at: boot.now(),
            watermark: 1,
        },
        PolicyVersion::new(7).unwrap(),
    );
    let policy: Arc<dyn PolicyView> = view;
    let now = clock
        .now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let verifier: Arc<dyn AccessTokenVerifier> = Arc::new(
        FakeAccessTokenVerifier::new()
            .accepting(GOOD, token(USER, "session-1", now))
            .accepting(OTHER, token(OTHER_USER, "session-2", now))
            .rejecting("expired.token.value", TokenRejection::Expired),
    );
    let memo: Arc<dyn TokenMemo> = Arc::new(MokaTokenMemo::new(
        TokenMemoSettings {
            capacity: 1_000,
            max_ttl: Duration::from_mins(5),
        },
        Arc::clone(clock),
    ));
    let revocations: Arc<dyn RevocationView> =
        Arc::new(SnapshotRevocationView::new(Arc::clone(&policy)));
    let tokens = Arc::new(CachingTokenRepository::new(verifier, memo, revocations));
    let token_port: Arc<dyn TokenRepository> = Arc::<CachingTokenRepository>::clone(&tokens);
    let commands: Arc<dyn CommandBus> = Arc::new(UnauditedCommands);
    let authorizer = RequestAuthorizer::new(
        token_port,
        Arc::clone(clock),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
        commands,
    );
    let pipeline = Pipeline::new(
        policy,
        freshness,
        tokens,
        Arc::new(authorizer),
        Arc::new(Ok200),
    )
    .with_access_log(access.pipeline_step(clock));
    router(pipeline)
}

pub(crate) fn request(path: &str, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::get(path).header("host", HOST);
    if let Some(token) = token {
        builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    builder.body(Body::empty()).unwrap()
}

async fn send(harness: &Harness, request: Request<Body>) -> StatusCode {
    harness
        .router
        .clone()
        .oneshot(request)
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn each_decision_goes_to_exactly_one_lane_by_the_rule() {
    let harness = harness(SampleRate::ALL, 1);

    assert_eq!(
        send(&harness, request("/api/users/1", Some(OTHER))).await,
        StatusCode::FORBIDDEN
    );
    for path in [
        "/api/audit-me",
        "/api/secret",
        "/api/wild/9",
        "/api/users/1",
    ] {
        assert_eq!(
            send(&harness, request(path, Some(GOOD))).await,
            StatusCode::OK
        );
    }
    harness.access.finish();

    let audit = harness.sink.records(AccessLane::Audit);
    let ordinary = harness.sink.records(AccessLane::Access);
    let mut audited: Vec<(String, AccessDecision)> = audit
        .iter()
        .map(|record| (record.route_template.clone().unwrap(), record.decision))
        .collect();
    audited.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then(left.1.as_str().cmp(right.1.as_str()))
    });
    assert_eq!(
        audited,
        [
            ("/api/audit-me".to_owned(), AccessDecision::Allow),
            ("/api/secret".to_owned(), AccessDecision::Allow),
            ("/api/users/{id}".to_owned(), AccessDecision::Deny),
            ("/api/wild/{id}".to_owned(), AccessDecision::Allow),
        ]
    );
    assert_eq!(ordinary.len(), 1);
    assert_eq!(
        ordinary[0].route_template.as_deref(),
        Some("/api/users/{id}")
    );
    assert_eq!(ordinary[0].decision, AccessDecision::Allow);
    assert_eq!(ordinary[0].reason, DecisionReason::Allowed);
    assert_eq!(ordinary[0].upstream.as_deref(), Some("backend"));
    assert_eq!(ordinary[0].status, 200);
    assert_eq!(ordinary[0].policy_version, Some(7));
    assert_eq!(
        ordinary[0].subject_kind.map(SubjectKind::as_str),
        Some("user")
    );
    assert_eq!(harness.sink.entries().len(), 5);
}

#[tokio::test]
async fn the_denial_names_the_reason_the_denied_key_and_the_subject() {
    let harness = harness(SampleRate::NONE, 1);

    send(&harness, request("/api/users/1", Some(OTHER))).await;
    send(
        &harness,
        request("/api/users/1", Some("expired.token.value")),
    )
    .await;
    send(&harness, request("/api/users/1", None)).await;
    send(&harness, request("/api/nowhere", Some(GOOD))).await;
    harness.access.finish();

    let records = harness.sink.records(AccessLane::Audit);
    assert_eq!(records.len(), 4);
    assert_eq!(records[0].reason, DecisionReason::PermissionMissing);
    assert_eq!(records[0].denied, ["rest:users:GET /api/users/{}"]);
    assert_eq!(records[0].subject_id.as_deref(), Some(OTHER_USER));
    assert_eq!(records[1].reason, DecisionReason::TokenExpired);
    assert!(records[1].subject_id.is_none());
    assert_eq!(records[2].reason, DecisionReason::TokenMissing);
    assert_eq!(records[3].reason, DecisionReason::UnknownOperation);
    assert!(records[3].route_id.is_none());
    assert!(
        records
            .iter()
            .all(|record| record.decision == AccessDecision::Deny)
    );
}

#[tokio::test]
async fn exactly_the_expected_sample_of_ordinary_allows_is_written() {
    let seed = TestRng::from_env().seed();
    let rate = SampleRate::parse("0.25").unwrap();
    let requests = 400_usize;
    let replay = FakeRng::seeded(seed);
    let expected = (0..requests)
        .filter(|_| rate.admits(replay.next_u64()))
        .count();
    let harness = harness(rate, seed);

    for _ in 0..requests {
        assert_eq!(
            send(&harness, request("/api/users/1", Some(GOOD))).await,
            StatusCode::OK
        );
    }
    harness.access.finish();

    assert_eq!(harness.sink.records(AccessLane::Access).len(), expected);
    assert!(expected > 0 && expected < requests, "{expected}");
    assert_eq!(harness.sink.records(AccessLane::Audit).len(), 0);
}

#[tokio::test]
async fn no_written_record_holds_the_credential_the_cookie_the_document_or_the_concrete_path() {
    let harness = harness(SampleRate::ALL, 1);
    let secret_document = "{ secretDocument { id } }";
    let concrete = Request::get("/api/users/424242?apiKey=hunter2")
        .header("host", HOST)
        .header(AUTHORIZATION, format!("Bearer {GOOD}"))
        .header(COOKIE, "session=cookie-secret-value")
        .body(Body::from(secret_document))
        .unwrap();

    assert_eq!(send(&harness, concrete).await, StatusCode::OK);
    assert_eq!(
        send(&harness, request("/api/users/424243", Some(OTHER))).await,
        StatusCode::FORBIDDEN
    );
    harness.access.finish();

    let lines: Vec<String> = harness
        .sink
        .entries()
        .iter()
        .map(|(lane, entry)| render_entry(*lane, entry))
        .collect();
    assert_eq!(lines.len(), 2);
    for line in &lines {
        for forbidden in [
            GOOD,
            OTHER,
            "cookie-secret-value",
            "secretDocument",
            "424242",
            "424243",
            "hunter2",
            "apiKey",
        ] {
            assert!(!line.contains(forbidden), "{forbidden} in {line}");
        }
        assert!(line.contains("/api/users/{id}"));
    }
    for record in harness
        .sink
        .records(AccessLane::Access)
        .into_iter()
        .chain(harness.sink.records(AccessLane::Audit))
    {
        let prefix = record.credential_digest_prefix.unwrap();
        assert_eq!(prefix.len(), 8);
        assert!(
            prefix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
    }
}

#[tokio::test]
async fn a_request_without_a_credential_has_no_digest_prefix() {
    let harness = harness(SampleRate::ALL, 1);

    send(&harness, request("/api/users/1", None)).await;
    harness.access.finish();

    let records = harness.sink.records(AccessLane::Audit);
    assert_eq!(records.len(), 1);
    assert!(records[0].credential_digest_prefix.is_none());
}

fn facts(reason: DecisionReason) -> AccessFacts {
    AccessFacts {
        decision_id: Uuid::parse("00000000-0000-7000-8000-000000000001").unwrap(),
        occurred_at: at(NOW),
        request: RequestFacts {
            method: "GET".to_owned(),
            host: HOST.to_owned(),
            request_id: Some("req-1".to_owned()),
            bytes_in: 0,
            credential_digest_prefix: Some("0a1b2c3d".to_owned()),
        },
        route: Some(RouteFacts {
            id: Some(Uuid::parse("00000000-0000-7000-8000-000000000100").unwrap()),
            template: "/api/users/{id}".to_owned(),
            upstream: Some("backend".to_owned()),
        }),
        verdict: VerdictFacts {
            decision: reason.decision(),
            reason,
            subject: Some(SubjectId::User(Uuid::parse(USER).unwrap())),
            policy_version: Some(7),
            trace: DecisionTrace::default(),
            denied: Vec::new(),
            project_id: None,
        },
        response: ResponseFacts {
            status: 200,
            bytes_out: 0,
            latency_us: 10,
        },
    }
}

#[tokio::test]
async fn a_would_deny_of_a_route_in_audit_mode_is_written_with_its_reason() {
    let sink = Arc::new(RecordingAccessLogSink::new());
    let access = AccessLogAdapters::start(
        &AccessLogSettings {
            allow_sample_rate: SampleRate::NONE,
            class_budgets: ClassBudgets::default(),
            channel_capacity: 16,
        },
        Arc::new(FakeRng::seeded(1)),
        Arc::new(FixedClock::at(at(NOW))),
        Arc::<RecordingAccessLogSink>::clone(&sink),
    )
    .unwrap();

    access
        .recorder()
        .record(facts(DecisionReason::AuditModeWouldDeny));
    access.finish();

    let records = sink.records(AccessLane::Audit);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].reason, DecisionReason::AuditModeWouldDeny);
    assert_eq!(records[0].status, 200);
    let line = render_entry(
        AccessLane::Audit,
        &AccessEntry::Record(Box::new(records[0].clone())),
    );
    assert!(line.contains("\"reason\":\"audit_mode_would_deny\""));
}

#[tokio::test]
async fn a_request_the_decision_denies_on_a_route_in_audit_mode_is_forwarded_and_counted_by_its_reason()
 {
    let (recorder, _guard) = LogRecorder::install();
    let harness = harness(SampleRate::NONE, 1);

    let audited = send(&harness, request("/api/audit-mode/1", Some(GOOD))).await;
    let enforced = send(&harness, request("/api/enforce-mode/1", Some(GOOD))).await;
    let anonymous = send(&harness, request("/api/audit-mode/1", None)).await;
    harness.access.finish();

    assert_eq!(audited, StatusCode::OK);
    assert_eq!(enforced, StatusCode::FORBIDDEN);
    assert_eq!(anonymous, StatusCode::UNAUTHORIZED);
    let reasons: Vec<DecisionReason> = harness
        .sink
        .records(AccessLane::Audit)
        .iter()
        .map(|record| record.reason)
        .collect();
    assert_eq!(
        reasons,
        [
            DecisionReason::AuditModeWouldDeny,
            DecisionReason::PermissionMissing,
            DecisionReason::TokenMissing,
        ]
    );
    let counted: Vec<String> = recorder
        .lines()
        .iter()
        .filter(|line| line.field("metric") == Some("gateway_decisions_total"))
        .filter_map(|line| line.field("reason").map(str::to_owned))
        .collect();
    assert!(
        counted.contains(&"audit_mode_would_deny".to_owned()),
        "{counted:?}"
    );
}

#[tokio::test]
async fn five_thousand_errors_in_one_second_write_the_budget_and_one_aggregate() {
    let sink = Arc::new(RecordingAccessLogSink::new());
    let access = AccessLogAdapters::start(
        &AccessLogSettings {
            allow_sample_rate: SampleRate::NONE,
            class_budgets: ClassBudgets::new(1_000, 2_000),
            channel_capacity: 8_192,
        },
        Arc::new(FakeRng::seeded(1)),
        Arc::new(FixedClock::at(at(NOW))),
        Arc::<RecordingAccessLogSink>::clone(&sink),
    )
    .unwrap();
    let recorder = access.recorder();

    for _ in 0..5_000 {
        let mut unavailable = facts(DecisionReason::Unavailable);
        unavailable.response.status = 503;
        recorder.record(unavailable);
    }
    access.finish();

    assert_eq!(sink.records(AccessLane::Access).len(), 1_000);
    let aggregates = sink.aggregates();
    assert_eq!(aggregates.len(), 1);
    assert_eq!(aggregates[0].count, 4_000);
    assert_eq!(aggregates[0].class, AccessClass::Error);
    assert_eq!(aggregates[0].status, 503);
    assert_eq!(
        access
            .counters()
            .dropped_count(AccessLane::Access, AccessClass::Error),
        0
    );
}

/// The channel send of a full channel, measured on this host: its p99 is printed next to the 1 ms
/// target of NFR-24, which is a target and not an assertion.
#[tokio::test]
async fn a_full_channel_never_waits_and_its_send_p99_is_printed_next_to_the_target() {
    let counters = Arc::new(AccessLogCounters::new());
    let (channel, _receiver) = access_log_channel(1, Arc::clone(&counters));
    let recorder = AccessRecorder::new(
        AccessRecordBuilder::new(Arc::new(FakeRng::seeded(3)), SampleRate::ALL),
        channel,
    );
    recorder.record(facts(DecisionReason::PermissionMissing));
    let sends = 10_000_usize;
    let p99_index = 9_899_usize;
    let mut samples = Vec::with_capacity(sends);

    for _ in 0..sends {
        let denied = facts(DecisionReason::PermissionMissing);
        let started = Instant::now();
        recorder.record(denied);
        samples.push(started.elapsed());
    }

    samples.sort_unstable();
    let p99 = samples[p99_index];
    println!(
        "access log channel send with a full channel: p99 = {p99:?}, target (NFR-24) = 1ms, {sends} sends on this host"
    );
    assert_eq!(
        counters.dropped_count(AccessLane::Audit, AccessClass::Audit),
        u64::try_from(sends).unwrap()
    );
}
