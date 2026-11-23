use std::path::PathBuf;

use test_support::access_token::DEVELOPMENT_PUBLIC_KEYS_FILE;
use tokio::sync::watch;

use super::*;
use crate::cli::GatewayArgs;

fn config() -> GatewayConfig {
    let mut args = GatewayArgs::default();
    args.service.app_env = Some("test".to_owned());
    args.service.tokens.public_keys_file = Some(DEVELOPMENT_PUBLIC_KEYS_FILE.to_owned());
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

#[test]
fn the_task_set_is_empty_until_story_9_3() {
    let adapters = GatewayAdapters::from_config(&config()).unwrap();
    let (_stop, stopping) = watch::channel(false);

    let tasks = start_tasks(&adapters, stopping);

    assert!(tasks.is_empty());
}
