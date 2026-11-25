//! The rate limit variables of the gateway: `RATE_LIMIT_STORE_URL`, `RATE_LIMIT_STORE_TIMEOUT`
//! and `RATE_LIMIT_BREAKER_OPEN_DURATION`.

use std::time::Duration;

use iam_infrastructure::ValkeyEndpoint;
use rstest::rstest;

use super::{gateway_problems, some, valid_gateway};
use crate::config::{DEFAULT_RATE_LIMIT_STORE_URL, GatewayConfig};

#[test]
fn the_defaults_are_the_local_valkey_ten_milliseconds_and_a_five_second_breaker() {
    let config = GatewayConfig::from_args(&valid_gateway()).unwrap();

    assert_eq!(
        config.rate_limit.store,
        ValkeyEndpoint::Direct(DEFAULT_RATE_LIMIT_STORE_URL.to_owned())
    );
    assert_eq!(config.rate_limit.store_timeout, Duration::from_millis(10));
    assert_eq!(
        config.rate_limit.breaker_open_duration,
        Duration::from_secs(5)
    );
}

#[rstest]
#[case("redis://valkey:6379")]
#[case("redis+sentinel://sentinel-0:26379,sentinel-1:26379/iam-rate-limit")]
fn a_valkey_url_is_taken_as_given(#[case] url: &str) {
    let mut args = valid_gateway();
    args.rate_limit_store_url = some(url);

    let config = GatewayConfig::from_args(&args).unwrap();

    assert_eq!(config.rate_limit.store, ValkeyEndpoint::parse(url).unwrap());
}

#[rstest]
#[case("")]
#[case("memcached://valkey:11211")]
#[case("redis+sentinel://sentinel:26379")]
fn a_url_that_names_no_valkey_names_its_variable_and_never_echoes_it(#[case] url: &str) {
    let mut args = valid_gateway();
    args.rate_limit_store_url = some(url);

    let problems = gateway_problems(&args);

    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].0, "RATE_LIMIT_STORE_URL");
    assert!(url.is_empty() || !problems[0].1.contains(url));
}

#[rstest]
#[case("1ms", 1)]
#[case("10ms", 10)]
#[case("50ms", 50)]
fn a_timeout_from_one_to_fifty_milliseconds_is_taken_as_given(
    #[case] raw: &str,
    #[case] millis: u64,
) {
    let mut args = valid_gateway();
    args.rate_limit_store_timeout = some(raw);

    let config = GatewayConfig::from_args(&args).unwrap();

    assert_eq!(
        config.rate_limit.store_timeout,
        Duration::from_millis(millis)
    );
}

#[rstest]
#[case("0s")]
#[case("999us")]
#[case("51ms")]
#[case("1s")]
#[case("fast")]
fn a_timeout_outside_one_to_fifty_milliseconds_names_its_variable(#[case] raw: &str) {
    let mut args = valid_gateway();
    args.rate_limit_store_timeout = some(raw);

    let problems = gateway_problems(&args);

    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].0, "RATE_LIMIT_STORE_TIMEOUT");
}

#[rstest]
#[case("1s", 1)]
#[case("5s", 5)]
#[case("5m", 300)]
fn a_breaker_open_duration_from_one_second_to_five_minutes_is_taken_as_given(
    #[case] raw: &str,
    #[case] seconds: u64,
) {
    let mut args = valid_gateway();
    args.rate_limit_breaker_open_duration = some(raw);

    let config = GatewayConfig::from_args(&args).unwrap();

    assert_eq!(
        config.rate_limit.breaker_open_duration,
        Duration::from_secs(seconds)
    );
}

#[rstest]
#[case("0s")]
#[case("999ms")]
#[case("301s")]
#[case("1h")]
#[case("slow")]
fn a_breaker_open_duration_outside_one_second_to_five_minutes_names_its_variable(
    #[case] raw: &str,
) {
    let mut args = valid_gateway();
    args.rate_limit_breaker_open_duration = some(raw);

    let problems = gateway_problems(&args);

    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].0, "RATE_LIMIT_BREAKER_OPEN_DURATION");
}
