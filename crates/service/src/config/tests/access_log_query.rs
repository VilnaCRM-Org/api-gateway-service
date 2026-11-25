//! The access decision query variables of `serve`: `LOKI_QUERY_URL`, `LOKI_TENANT_ID`,
//! `ACCESS_LOG_QUERY_MAX_RANGE` and `ACCESS_LOG_QUERY_TIMEOUT`.

use std::time::Duration;

use rstest::rstest;

use super::{problems, some, valid, variables};
use crate::config::{AppEnv, Config, DEFAULT_LOKI_QUERY_URL, DEFAULT_MAX_RANGE, DEFAULT_TIMEOUT};

#[test]
fn the_values_that_are_set_are_taken_as_given() {
    let mut args = valid();
    args.access_log_query.loki_query_url = some("http://loki:3100");
    args.access_log_query.loki_tenant_id = some("tenant-7");
    args.access_log_query.max_range = some("2h");
    args.access_log_query.timeout = some("750ms");

    let settings = Config::from_args(args).unwrap().access_log_query;

    assert_eq!(settings.query_url.to_string(), "http://loki:3100/");
    assert_eq!(settings.tenant_id, "tenant-7");
    assert_eq!(settings.max_range, Duration::from_hours(2));
    assert_eq!(settings.timeout, Duration::from_millis(750));
}

#[test]
fn the_defaults_are_a_day_and_five_seconds_with_the_tenant_iam() {
    let settings = Config::from_args(valid()).unwrap().access_log_query;

    assert_eq!(settings.max_range, DEFAULT_MAX_RANGE);
    assert_eq!(settings.max_range, Duration::from_hours(24));
    assert_eq!(settings.timeout, DEFAULT_TIMEOUT);
    assert_eq!(settings.timeout, Duration::from_secs(5));
    assert_eq!(settings.tenant_id, "iam");
}

#[rstest]
#[case::dev("dev")]
#[case::test("test")]
fn the_compose_loki_is_the_default_url_in_dev_and_test(#[case] environment: &str) {
    let mut args = valid();
    args.app_env = some(environment);
    args.access_log_query.loki_query_url = None;

    let settings = Config::from_args(args).unwrap().access_log_query;

    assert_eq!(
        settings.query_url.to_string().trim_end_matches('/'),
        DEFAULT_LOKI_QUERY_URL
    );
}

#[test]
fn a_missing_url_outside_dev_and_test_is_a_problem() {
    let mut args = valid();
    args.access_log_query.loki_query_url = None;

    assert_eq!(
        problems(args),
        [(
            "LOKI_QUERY_URL",
            "is required outside APP_ENV dev and test".to_owned()
        )]
    );
}

#[rstest]
#[case::https("https://loki:3100")]
#[case::no_scheme("loki:3100")]
#[case::unparsable("http://lo ki:3100")]
#[case::with_a_path("http://loki:3100/loki")]
#[case::with_a_query("http://loki:3100/?a=b")]
fn a_url_that_is_not_a_bare_http_url_names_its_variable(#[case] raw: &str) {
    let mut args = valid();
    args.access_log_query.loki_query_url = some(raw);

    assert_eq!(variables(args), ["LOKI_QUERY_URL"]);
}

#[rstest]
#[case::zero("0s")]
#[case::above_a_week("169h")]
#[case::not_a_duration("soon")]
fn a_range_out_of_bounds_names_its_variable(#[case] raw: &str) {
    let mut args = valid();
    args.access_log_query.max_range = some(raw);

    assert_eq!(variables(args), ["ACCESS_LOG_QUERY_MAX_RANGE"]);
}

#[rstest]
#[case::zero("0s")]
#[case::above_two_minutes("121s")]
#[case::not_a_duration("soon")]
fn a_timeout_out_of_bounds_names_its_variable(#[case] raw: &str) {
    let mut args = valid();
    args.access_log_query.timeout = some(raw);

    assert_eq!(variables(args), ["ACCESS_LOG_QUERY_TIMEOUT"]);
}

#[rstest]
#[case("")]
#[case("two words")]
fn a_tenant_that_cannot_be_a_header_value_names_its_variable(#[case] raw: &str) {
    let mut args = valid();
    args.access_log_query.loki_tenant_id = some(raw);

    assert_eq!(variables(args), ["LOKI_TENANT_ID"]);
}

#[test]
fn the_environment_label_of_an_app_environment_is_the_label_of_its_decisions() {
    assert_eq!(crate::config::env_label(AppEnv::Test), "test");
}
