//! The production telemetry on a captured writer with an application whose probe panics.
//!
//! The test installs the global subscriber and the panic hook, so it relies on nextest giving
//! every test its own process.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use clap::Parser as _;
use health_check_domain::Dependency;
use http_body_util::BodyExt as _;
use iam_application::MaintenanceSettings;
use iam_domain::{BulkChunker, BulkPacing};
use iam_infrastructure::BufferedRejectedAttemptLog;
use serde_json::Value;
use service::bootstrap::{Adapters, event_bus, router};
use service::cli::{Cli, Command};
use service::config::{BulkSettings, Config};
use service::telemetry;
use test_support::access_token::{DEVELOPMENT_PUBLIC_KEYS_FILE, FakeAccessTokenVerifier};
use test_support::anti_entropy::FakePolicyLogTail;
use test_support::bulk_operation::{FakeBulkOperationRepository, FakeBulkRoleTargetStore};
use test_support::change_receipt::FakeChangeReceiptRepository;
use test_support::clock::FixedClock;
use test_support::graphql_permission::FakeGraphQlPermissionRepository;
use test_support::graphql_spec::FakeGraphQlSpecRepository;
use test_support::id::SequenceUuidGenerator;
use test_support::idempotency::FakeIdempotencyRepository;
use test_support::maintenance_store::FakeMaintenanceStore;
use test_support::openapi_spec::FakeOpenApiSpecRepository;
use test_support::policy_epoch::FakePolicyEpochRepository;
use test_support::policy_read::FakePolicyReadRepository;
use test_support::policy_state_inventory::FakePolicyStateInventory;
use test_support::probe::StubProbe;
use test_support::rate_policy::FakeRatePolicyRepository;
use test_support::repository::InMemoryExampleApiResourceRepository;
use test_support::request_digester::FakeRequestDigester;
use test_support::rest_permission::FakeRestPermissionRepository;
use test_support::revocation::FakeRevocationRepository;
use test_support::role::FakeRoleRepository;
use test_support::route::FakeRouteRepository;
use test_support::security_audit::FakeSecurityAuditLog;
use test_support::singleton_leadership::FakeSingletonLeadership;
use test_support::startup_lock::FakeStartupLock;
use test_support::task_state::FakeTaskStateRepository;
use test_support::token::FakeTokenRepository;
use test_support::unit_of_work::FakeIamUnitOfWork;
use test_support::upstream::FakeUpstreamRepository;
use test_support::user_role::FakeUserRoleRepository;
use tower::ServiceExt as _;

const REQUEST_ID: &str = "panic-test-1";

/// An in-memory log sink that the test reads back.
#[derive(Debug, Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_poisoned| io::ErrorKind::Other)?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn config() -> Config {
    let Command::Serve(mut args) = Cli::parse_from(["service", "serve"]).command else {
        panic!("`serve` arguments expected");
    };
    args.aws_region = Some("us-east-1".to_owned());
    args.database.url = Some("postgres://app:unused@127.0.0.1:1/app".to_owned());
    args.tokens.public_keys_file = Some(DEVELOPMENT_PUBLIC_KEYS_FILE.to_owned());
    Config::from_args(args).unwrap()
}

#[tokio::test]
async fn a_panic_is_one_json_line_with_the_request_id_and_a_500_problem() {
    let output = Captured::default();
    let sink = output.clone();
    telemetry::init("info", move || sink.clone()).unwrap();
    let adapters = Adapters {
        repository: Arc::new(InMemoryExampleApiResourceRepository::new()),
        policy_epochs: Arc::new(FakePolicyEpochRepository::new()),
        policy_reads: Arc::new(FakePolicyReadRepository::new()),
        bulk_operations: Arc::new(FakeBulkOperationRepository::new()),
        bulk_targets: Arc::new(FakeBulkRoleTargetStore::new()),
        bulk: BulkSettings {
            chunker: BulkChunker::new(1_000).unwrap(),
            pacing: BulkPacing::new(2_000).unwrap(),
        },
        policy_inventory: Arc::new(FakePolicyStateInventory::new()),
        policy_tail: Arc::new(FakePolicyLogTail::with(Vec::new())),
        security_audit_log: Arc::new(FakeSecurityAuditLog::new()),
        startup_lock: Arc::new(FakeStartupLock::new()),
        singleton_leadership: Arc::new(FakeSingletonLeadership::leading()),
        maintenance_store: Arc::new(FakeMaintenanceStore::new()),
        task_states: Arc::new(FakeTaskStateRepository::new()),
        maintenance: MaintenanceSettings::default(),
        outbox_relay: None,
        change_receipts: Arc::new(FakeChangeReceiptRepository::new()),
        idempotency_records: Arc::new(FakeIdempotencyRepository::new()),
        roles: Arc::new(FakeRoleRepository::new()),
        upstreams: Arc::new(FakeUpstreamRepository::new()),
        routes: Arc::new(FakeRouteRepository::new()),
        rate_policies: Arc::new(FakeRatePolicyRepository::new()),
        unit_of_work: Arc::new(FakeIamUnitOfWork::new()),
        write_unit_of_work: Arc::new(FakeIamUnitOfWork::new()),
        request_digester: Arc::new(FakeRequestDigester),
        user_roles: Arc::new(FakeUserRoleRepository::new()),
        graphql_specs: Arc::new(FakeGraphQlSpecRepository::new()),
        openapi_specs: Arc::new(FakeOpenApiSpecRepository::new()),
        graphql_permissions: Arc::new(FakeGraphQlPermissionRepository::new()),
        rest_permissions: Arc::new(FakeRestPermissionRepository::new()),
        access_tokens: Arc::new(FakeAccessTokenVerifier::new()),
        tokens: Arc::new(FakeTokenRepository::new()),
        revocations: Arc::new(FakeRevocationRepository::new()),
        rejected_attempts: Arc::new(BufferedRejectedAttemptLog::new()),
        probes: vec![Arc::new(StubProbe::panicking(Dependency::Database))],
        event_bus: event_bus(),
        clock: Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        uuid_generator: Arc::new(SequenceUuidGenerator::starting_at(1)),
    };
    let request = Request::get("/api/health")
        .header("x-request-id", REQUEST_ID)
        .body(Body::empty())
        .unwrap();

    let response = router(adapters, &config())
        .unwrap()
        .oneshot(request)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response.headers()["content-type"],
        "application/problem+json"
    );
    assert_eq!(response.headers()["x-request-id"], REQUEST_ID);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let problem: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(problem["status"], 500);
    let captured = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    let lines: Vec<Value> = captured
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let messages: Vec<&str> = lines
        .iter()
        .map(|line| line["message"].as_str().unwrap())
        .collect();
    assert_eq!(
        messages,
        ["panic", "request failed", "request completed"],
        "{captured}"
    );
    assert!(
        lines
            .iter()
            .all(|line| line["span"]["request_id"] == REQUEST_ID),
        "{captured}"
    );
    assert_eq!(lines[0]["level"], "ERROR");
    assert!(
        lines[0]["panic"]
            .as_str()
            .unwrap()
            .contains("stub probe panic"),
        "{captured}"
    );
}
