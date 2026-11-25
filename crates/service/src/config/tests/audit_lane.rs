//! The audit lane variables of the gateway: `LOKI_PUSH_URL`, `LOKI_TENANT_ID`,
//! `ACCESS_LOG_AUDIT_FLUSH_INTERVAL` and `ACCESS_LOG_AUDIT_MAX_PENDING`.

use std::time::Duration;

use rstest::rstest;

use super::{gateway_problems, over_sasl_ssl, some, valid_gateway};
use crate::config::{
    AppEnv, DEFAULT_LOKI_PUSH_URL, DEFAULT_LOKI_TENANT_ID, GatewayConfig, env_label,
};

#[test]
fn the_defaults_are_the_compose_loki_and_the_documented_bounds() {
    let config = GatewayConfig::from_args(&valid_gateway()).unwrap();

    assert_eq!(
        config.audit_lane.push_url.to_string(),
        DEFAULT_LOKI_PUSH_URL
    );
    assert_eq!(config.audit_lane.tenant_id, DEFAULT_LOKI_TENANT_ID);
    assert_eq!(config.audit_lane.flush_interval, Duration::from_secs(1));
    assert_eq!(config.audit_lane.max_pending, Duration::from_secs(5));
}

#[test]
fn the_values_that_are_set_are_taken_as_given() {
    let mut args = valid_gateway();
    args.loki_push_url = some("http://loki:3100/loki/api/v1/push");
    args.loki_tenant_id = some("tenant-7");
    args.access_log_audit_flush_interval = some("250ms");
    args.access_log_audit_max_pending = some("2s");

    let config = GatewayConfig::from_args(&args).unwrap();

    assert_eq!(
        config.audit_lane.push_url.to_string(),
        "http://loki:3100/loki/api/v1/push"
    );
    assert_eq!(config.audit_lane.tenant_id, "tenant-7");
    assert_eq!(config.audit_lane.flush_interval, Duration::from_millis(250));
    assert_eq!(config.audit_lane.max_pending, Duration::from_secs(2));
}

#[test]
fn a_missing_push_url_outside_dev_and_test_names_its_variable() {
    let mut args = valid_gateway();
    args.service.app_env = some("prod");
    over_sasl_ssl(&mut args);
    args.tls_cert_file = some("/etc/tls/tls.crt");
    args.tls_key_file = some("/etc/tls/tls.key");

    let problems = gateway_problems(&args);

    assert!(
        problems
            .iter()
            .any(|(variable, reason)| *variable == "LOKI_PUSH_URL"
                && reason.as_str() == "is required outside APP_ENV dev and test")
    );
}

#[rstest]
#[case("https://loki:3100/loki/api/v1/push")]
#[case("loki:3100")]
#[case("/loki/api/v1/push")]
#[case("http://loki:3100/loki/api/v1/push?x=1")]
#[case("")]
fn a_push_url_that_is_not_a_plain_http_url_names_its_variable(#[case] raw: &str) {
    let mut args = valid_gateway();
    args.loki_push_url = some(raw);

    let problems = gateway_problems(&args);

    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].0, "LOKI_PUSH_URL");
    assert!(problems[0].1.starts_with("must be an http:// URL"));
}

#[rstest]
#[case("")]
#[case("two words")]
#[case("tab\there")]
fn a_tenant_that_cannot_be_a_header_value_names_its_variable(#[case] raw: &str) {
    let mut args = valid_gateway();
    args.loki_tenant_id = some(raw);

    let problems = gateway_problems(&args);

    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].0, "LOKI_TENANT_ID");
}

#[rstest]
#[case("0s")]
#[case("soon")]
#[case("2m")]
fn an_unusable_flush_interval_names_its_variable(#[case] raw: &str) {
    let mut args = valid_gateway();
    args.access_log_audit_flush_interval = some(raw);

    let problems = gateway_problems(&args);

    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].0, "ACCESS_LOG_AUDIT_FLUSH_INTERVAL");
}

#[rstest]
#[case("0s")]
#[case("never")]
#[case("11m")]
fn an_unusable_max_pending_names_its_variable(#[case] raw: &str) {
    let mut args = valid_gateway();
    args.access_log_audit_max_pending = some(raw);

    let problems = gateway_problems(&args);

    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].0, "ACCESS_LOG_AUDIT_MAX_PENDING");
}

#[test]
fn a_max_pending_that_is_not_longer_than_the_flush_interval_is_refused() {
    let mut args = valid_gateway();
    args.access_log_audit_flush_interval = some("5s");
    args.access_log_audit_max_pending = some("5s");

    let problems = gateway_problems(&args);

    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].0, "ACCESS_LOG_AUDIT_MAX_PENDING");
    assert_eq!(
        problems[0].1,
        "must be longer than ACCESS_LOG_AUDIT_FLUSH_INTERVAL"
    );
}

#[test]
fn the_env_label_is_the_deployment_environment() {
    assert_eq!(env_label(AppEnv::Dev), "dev");
    assert_eq!(env_label(AppEnv::Test), "test");
    assert_eq!(env_label(AppEnv::Prod), "prod");
}
