use std::any::TypeId;
use std::time::Duration;

use axum::body::Body;
use axum::http::Request;
use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{
    BootClock as _, BootInstant, FreshnessRule, PolicyVersion, RouteId, UpstreamName,
};
use shared_domain::{Clock, Uuid};
use shared_infrastructure::clock::SystemClock;
use test_support::access_token::DEVELOPMENT_PUBLIC_KEYS_FILE;
use test_support::boot_clock::FakeBootClock;
use test_support::policy_view::FakePolicyView;
use tower::ServiceExt as _;

use super::*;
use crate::cli::GatewayArgs;

fn config() -> GatewayConfig {
    let mut args = GatewayArgs::default();
    args.service.app_env = Some("test".to_owned());
    args.service.tokens.public_keys_file = Some(DEVELOPMENT_PUBLIC_KEYS_FILE.to_owned());
    args.service.kafka.bootstrap_servers = Some("localhost:9092".to_owned());
    args.service.kafka.security_protocol = Some("PLAINTEXT".to_owned());
    GatewayConfig::from_args(&args).unwrap()
}

fn freshness() -> Arc<FreshnessState> {
    let clock = Arc::new(FakeBootClock::starting_at(BootInstant::from_elapsed(
        Duration::from_secs(100),
    )));
    let state = FreshnessState::new(
        FreshnessRule::new(Duration::from_secs(15), Duration::from_secs(2)),
        Arc::<FakeBootClock>::clone(&clock),
    );
    state.attach(
        FreshnessProof {
            taken_at: clock.now(),
            watermark: 1,
        },
        PolicyVersion::new(1).unwrap(),
    );
    Arc::new(state)
}

#[tokio::test]
async fn the_production_pipeline_answers_a_request_without_a_route_with_404() {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let pipeline = from_config(
        &config(),
        Arc::new(FakePolicyView::new()),
        freshness(),
        &clock,
        Arc::new(UnreachableUpstreams),
    )
    .unwrap();

    let response = super::super::router(pipeline)
        .oneshot(
            Request::get("/anything")
                .header("host", "api.example.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
}

#[test]
fn a_key_file_that_cannot_be_read_stops_the_wiring() {
    let mut config = config();
    config.tokens.public_keys_file = "/nonexistent/keys.pem".into();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);

    let outcome = from_config(
        &config,
        Arc::new(FakePolicyView::new()),
        freshness(),
        &clock,
        Arc::new(UnreachableUpstreams),
    );

    let error = outcome.unwrap_err();
    assert!(matches!(error, PipelineSetupError::Keys(_)));
    assert_ne!(error.to_string(), "");
}

#[tokio::test]
async fn the_placeholder_forwarder_reaches_no_upstream() {
    let target = UpstreamTarget::new(
        UpstreamName::new("users").unwrap(),
        RouteId::from_uuid(Uuid::parse("00000000-0000-0000-0000-000000000001").unwrap()),
    );

    let outcome = UnreachableUpstreams
        .forward(target, Request::new(Body::empty()))
        .await;

    assert_eq!(outcome.unwrap_err(), ForwardError::NoEndpoint);
}

#[tokio::test]
async fn the_unaudited_bus_takes_every_command_and_keeps_none() {
    let outcome = UnauditedCommands
        .dispatch_erased(TypeId::of::<u8>(), "Command", Box::new(1_u8))
        .await;

    assert!(outcome.is_ok());
}
