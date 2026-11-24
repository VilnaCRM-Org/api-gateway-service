use std::sync::Arc;
use std::time::Duration;

use iam_application::{EndpointDirectory, FreshnessState, ZoneSource};
use iam_domain::{FreshnessRule, ReadinessTransition, WatchTarget};
use test_support::access_token::DEVELOPMENT_PUBLIC_KEYS_FILE;
use test_support::boot_clock::FakeBootClock;
use test_support::peer_freshness_reader::FakePeerFreshnessReader;
use test_support::rng::FakeRng;

use super::ReadinessAdapters;
use crate::cli::GatewayArgs;
use crate::config::GatewayConfig;

fn config(floor: Option<&str>) -> GatewayConfig {
    let mut args = GatewayArgs::default();
    args.service.app_env = Some("test".to_owned());
    args.service.tokens.public_keys_file = Some(DEVELOPMENT_PUBLIC_KEYS_FILE.to_owned());
    args.service.kafka.bootstrap_servers = Some("localhost:9092".to_owned());
    args.service.kafka.security_protocol = Some("PLAINTEXT".to_owned());
    args.pod_name = Some("gateway-0".to_owned());
    args.readiness_az_floor = floor.map(str::to_owned);
    GatewayConfig::from_args(&args).unwrap()
}

fn peers() -> WatchTarget {
    WatchTarget {
        namespace: "iam".to_owned(),
        service: "iam-gateway-peers".to_owned(),
    }
}

fn directory() -> EndpointDirectory {
    EndpointDirectory::new(ZoneSource {
        peers: peers(),
        pod: Some("gateway-0".to_owned()),
        explicit: None,
    })
}

#[test]
fn the_adapters_take_the_floor_from_the_configuration_and_start_ready() {
    let adapters = ReadinessAdapters::from_config(
        &config(Some("3")),
        &directory(),
        peers(),
        Arc::new(FakeRng::seeded(1)),
    );

    assert_eq!(adapters.floor.pods(), 3);
    assert!(adapters.gate.is_ready());
    assert_eq!(adapters.peers.pod(), "gateway-0");
    assert!(format!("{adapters:?}").starts_with("ReadinessAdapters"));
}

#[test]
fn the_floor_defaults_to_one_pod() {
    let adapters = ReadinessAdapters::from_config(
        &config(None),
        &directory(),
        peers(),
        Arc::new(FakeRng::seeded(1)),
    );

    assert_eq!(adapters.floor.pods(), 1);
}

#[tokio::test]
async fn the_checker_over_the_adapters_keeps_a_pod_without_peers_ready() {
    let adapters = ReadinessAdapters::with(
        &config(None),
        &directory(),
        peers(),
        Arc::new(FakePeerFreshnessReader::new()),
        Arc::new(FakeRng::seeded(1)),
    );
    let state = Arc::new(FreshnessState::new(
        FreshnessRule::new(Duration::from_secs(15), Duration::from_secs(2)),
        Arc::new(FakeBootClock::new()),
    ));

    let checker = adapters.checker(state);

    for _ in 0..3 {
        assert_eq!(checker.check_once().await, ReadinessTransition::Unchanged);
    }
    assert!(adapters.gate.is_ready());
}
