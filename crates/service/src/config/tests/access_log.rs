//! The access log variables of the gateway: `LOG_ALLOW_SAMPLE_RATE`, `LOG_CLASS_BUDGETS` and
//! `LOG_CHANNEL_CAPACITY`.

use iam_domain::{AccessClass, ClassBudgets, DEFAULT_CHANNEL_CAPACITY, SampleRate};
use rstest::rstest;

use super::{gateway_problems, some, valid_gateway};
use crate::config::GatewayConfig;

#[test]
fn the_defaults_are_the_documented_ones() {
    let config = GatewayConfig::from_args(&valid_gateway()).unwrap();

    assert_eq!(
        config.access_log.allow_sample_rate,
        SampleRate::parse("0.01").unwrap()
    );
    assert_eq!(
        config.access_log.class_budgets,
        ClassBudgets::new(1_000, 2_000)
    );
    assert_eq!(config.access_log.channel_capacity, DEFAULT_CHANNEL_CAPACITY);
    assert_eq!(config.access_log.channel_capacity, 65_536);
}

#[test]
fn the_values_that_are_set_are_taken_as_given() {
    let mut args = valid_gateway();
    args.log_allow_sample_rate = some("0.5");
    args.log_class_budgets = some("error=10,audit=20");
    args.log_channel_capacity = some("128");

    let config = GatewayConfig::from_args(&args).unwrap();

    assert_eq!(
        config.access_log.allow_sample_rate,
        SampleRate::parse("0.5").unwrap()
    );
    assert_eq!(
        config.access_log.class_budgets.of(AccessClass::Error),
        Some(10)
    );
    assert_eq!(
        config.access_log.class_budgets.of(AccessClass::Audit),
        Some(20)
    );
    assert_eq!(config.access_log.channel_capacity, 128);
}

#[rstest]
#[case("1.5")]
#[case("-0.1")]
#[case("2")]
#[case("often")]
#[case("")]
fn a_sample_rate_outside_zero_to_one_names_its_variable_and_never_echoes_it(#[case] raw: &str) {
    let mut args = valid_gateway();
    args.log_allow_sample_rate = some(raw);

    let problems = gateway_problems(&args);

    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].0, "LOG_ALLOW_SAMPLE_RATE");
    assert!(
        problems[0]
            .1
            .starts_with("must be a decimal number from 0 to 1")
    );
    assert!(raw.is_empty() || !problems[0].1.contains(raw));
}

#[rstest]
#[case("error")]
#[case("error=0")]
#[case("audit=x")]
#[case("allow=5")]
#[case("error=1,error=2")]
#[case("")]
fn an_unparsable_budget_names_its_variable(#[case] raw: &str) {
    let mut args = valid_gateway();
    args.log_class_budgets = some(raw);

    let problems = gateway_problems(&args);

    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].0, "LOG_CLASS_BUDGETS");
}

#[rstest]
#[case("0")]
#[case("16777217")]
#[case("lots")]
#[case("")]
fn a_channel_capacity_out_of_range_names_its_variable(#[case] raw: &str) {
    let mut args = valid_gateway();
    args.log_channel_capacity = some(raw);

    let problems = gateway_problems(&args);

    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].0, "LOG_CHANNEL_CAPACITY");
    assert_eq!(problems[0].1, "must be an integer from 1 to 16777216");
}

#[test]
fn every_problem_of_the_access_log_is_reported_at_once() {
    let mut args = valid_gateway();
    args.log_allow_sample_rate = some("9");
    args.log_class_budgets = some("nope");
    args.log_channel_capacity = some("0");

    let variables: Vec<&str> = gateway_problems(&args)
        .into_iter()
        .map(|(variable, _reason)| variable)
        .collect();

    assert_eq!(
        variables,
        [
            "LOG_ALLOW_SAMPLE_RATE",
            "LOG_CLASS_BUDGETS",
            "LOG_CHANNEL_CAPACITY"
        ]
    );
}
