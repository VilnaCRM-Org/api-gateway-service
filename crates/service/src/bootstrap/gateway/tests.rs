use std::path::PathBuf;

use test_support::access_token::DEVELOPMENT_PUBLIC_KEYS_FILE;
use test_support::endpoint_watch::DEVELOPMENT_ENDPOINTS_FILE;
use tokio::sync::watch;

use super::*;
use crate::cli::GatewayArgs;

fn config() -> GatewayConfig {
    let mut args = GatewayArgs::default();
    args.service.app_env = Some("test".to_owned());
    args.service.tokens.public_keys_file = Some(DEVELOPMENT_PUBLIC_KEYS_FILE.to_owned());
    args.service.kafka.bootstrap_servers = Some("localhost:9092".to_owned());
    args.service.kafka.security_protocol = Some("PLAINTEXT".to_owned());
    args.upstream_discovery = Some("static".to_owned());
    args.upstream_static_endpoints_file = Some(DEVELOPMENT_ENDPOINTS_FILE.to_owned());
    GatewayConfig::from_args(&args).unwrap()
}

#[test]
fn the_adapters_need_no_database_and_draw_from_the_operating_system() {
    let adapters = GatewayAdapters::from_config(&config()).unwrap();

    let first = adapters.rng.next_u64();
    let second = adapters.rng.next_u64();

    assert_ne!(first, second);
    assert!(format!("{adapters:?}").starts_with("GatewayAdapters"));
}

#[test]
fn a_key_file_that_cannot_be_parsed_fails_the_start() {
    let mut config = config();
    config.tokens.public_keys_file = PathBuf::from("/nonexistent/keys.pem");

    assert!(GatewayAdapters::from_config(&config).is_err());
}

#[tokio::test]
async fn the_endpoint_watcher_runs_for_the_services_of_the_static_file() {
    let adapters = GatewayAdapters::from_config(&config()).unwrap();
    let (stop, stopping) = watch::channel(false);

    let tasks = start_tasks(&adapters, stopping);

    assert_eq!(tasks.len(), 1);
    assert_eq!(adapters.endpoints.targets.len(), 1);
    stop.send_replace(true);
    assert_eq!(
        tasks.stop(std::time::Duration::from_secs(5)).await,
        crate::bootstrap::TaskStop::Drained
    );
}

#[tokio::test]
async fn the_watcher_publishes_the_endpoints_of_the_static_file() {
    let adapters = GatewayAdapters::from_config(&config()).unwrap();
    let (stop, stopping) = watch::channel(false);
    let mut view = adapters.endpoints.directory.view();
    let tasks = start_tasks(&adapters, stopping);

    assert!(view.changed().await);

    let target = adapters.endpoints.targets.first().unwrap();
    let endpoints = view.offered(target);
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints.first().unwrap().address(), "app");
    stop.send_replace(true);
    tasks.stop(std::time::Duration::from_secs(5)).await;
}

#[test]
fn a_static_file_without_services_starts_no_task() {
    let path =
        std::env::temp_dir().join(format!("gateway-no-services-{}.json", std::process::id()));
    std::fs::write(&path, "{}").unwrap();
    let mut config = config();
    config.endpoints.discovery = crate::config::UpstreamDiscovery::Static(path.clone());
    let adapters = GatewayAdapters::from_config(&config).unwrap();
    std::fs::remove_file(&path).unwrap_or_default();
    let (_stop, stopping) = watch::channel(false);

    let tasks = start_tasks(&adapters, stopping);

    assert!(tasks.is_empty());
}

#[test]
fn an_endpoint_file_that_cannot_be_used_fails_the_start() {
    let mut config = config();
    config.endpoints.discovery =
        crate::config::UpstreamDiscovery::Static(PathBuf::from("/nonexistent/endpoints.json"));

    let error = GatewayAdapters::from_config(&config).unwrap_err();

    assert!(matches!(error, GatewayAdapterError::Endpoints(_)));
}
