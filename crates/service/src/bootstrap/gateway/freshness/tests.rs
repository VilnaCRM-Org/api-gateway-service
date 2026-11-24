use std::sync::Arc;
use std::time::Duration;

use iam_application::ProofSink;
use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{Freshness, StaleCause};
use test_support::access_token::DEVELOPMENT_PUBLIC_KEYS_FILE;
use test_support::boot_clock::FakeBootClock;
use test_support::policy_view::FakePolicyView;

use super::FreshnessAdapters;
use crate::cli::GatewayArgs;
use crate::config::GatewayConfig;

#[derive(Debug)]
struct NoSink;

impl ProofSink for NoSink {
    fn offer(&self, _proof: FreshnessProof) {}
}

fn adapters() -> FreshnessAdapters {
    let mut args = GatewayArgs::default();
    args.service.app_env = Some("test".to_owned());
    args.service.tokens.public_keys_file = Some(DEVELOPMENT_PUBLIC_KEYS_FILE.to_owned());
    args.service.kafka.bootstrap_servers = Some("localhost:9092".to_owned());
    args.service.kafka.security_protocol = Some("PLAINTEXT".to_owned());
    args.freshness_probe_interval = Some("250ms".to_owned());
    let config = GatewayConfig::from_args(&args).unwrap();
    FreshnessAdapters::from_config(&config, Arc::new(FakeBootClock::new()))
}

#[test]
fn the_state_starts_without_a_proof_under_the_bounds_of_the_configuration() {
    let adapters = adapters();

    assert_eq!(
        adapters.state.verdict(),
        Freshness::Stale(StaleCause::NoProof)
    );
    assert_eq!(adapters.state.rule().hard_bound(), Duration::from_secs(15));
    assert_eq!(adapters.state.rule().ready_bound(), Duration::from_secs(2));
    assert_eq!(adapters.probe_interval, Duration::from_millis(250));
}

#[tokio::test]
async fn the_peer_set_is_empty_until_the_peer_client_is_wired() {
    let adapters = adapters();

    let versions = adapters.peers.applied_versions().await;

    assert_eq!(versions.len(), 0);
}

#[tokio::test]
async fn the_prober_is_built_over_the_state_of_the_adapters() {
    let adapters = adapters();

    let prober = adapters.prober(Arc::new(FakePolicyView::failing()), Arc::new(NoSink));
    prober.watchdog_tick();

    assert_eq!(
        adapters.state.verdict(),
        Freshness::Stale(StaleCause::NoProof)
    );
}
