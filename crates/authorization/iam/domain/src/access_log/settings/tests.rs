use rstest::rstest;

use super::{
    ClassBudgets, DEFAULT_CHANNEL_CAPACITY, InvalidAccessLogSetting, SampleRate,
    parse_channel_capacity,
};
use crate::access_log::kinds::AccessClass;

#[rstest]
#[case("0")]
#[case("0.0")]
#[case("0.01")]
#[case(".5")]
#[case("0.999999999")]
#[case("1")]
#[case("1.0")]
#[case("1.000000000")]
fn a_sample_rate_from_zero_to_one_is_accepted(#[case] text: &str) {
    assert!(SampleRate::parse(text).is_ok());
}

#[rstest]
#[case("")]
#[case(".")]
#[case("1.1")]
#[case("1.000000001")]
#[case("2")]
#[case("-0.1")]
#[case("0.0000000001")]
#[case("abc")]
#[case("0,5")]
#[case("1e-2")]
#[case(" 0.5")]
#[case("0.5 ")]
#[case("+0.5")]
fn a_sample_rate_outside_zero_to_one_or_unparsable_is_refused(#[case] text: &str) {
    assert_eq!(
        SampleRate::parse(text),
        Err(InvalidAccessLogSetting::SampleRate)
    );
}

#[test]
fn a_rate_of_one_admits_every_draw_and_a_rate_of_zero_none() {
    let draws = [0, 1, 999_999_999, 1_000_000_000, u64::MAX];
    assert!(draws.iter().all(|draw| SampleRate::ALL.admits(*draw)));
    assert!(draws.iter().all(|draw| !SampleRate::NONE.admits(*draw)));
    assert_eq!(SampleRate::parse("1").unwrap(), SampleRate::ALL);
    assert_eq!(SampleRate::parse("0").unwrap(), SampleRate::NONE);
}

#[test]
fn a_rate_admits_exactly_the_share_of_draws_it_names() {
    let rate = SampleRate::parse("0.01").unwrap();
    let admitted = (0..1_000_000_000_u64)
        .step_by(1_000)
        .filter(|draw| rate.admits(*draw))
        .count();
    assert_eq!(admitted, 10_000);
    assert!(rate.admits(9_999_999));
    assert!(!rate.admits(10_000_000));
}

#[test]
fn the_budgets_default_to_one_thousand_errors_and_two_thousand_audit_records() {
    let budgets = ClassBudgets::default();
    assert_eq!(budgets.of(AccessClass::Error), Some(1_000));
    assert_eq!(budgets.of(AccessClass::Audit), Some(2_000));
    assert_eq!(budgets.of(AccessClass::Allow), None);
    assert_eq!(
        ClassBudgets::parse("error=1000,audit=2000").unwrap(),
        budgets
    );
}

#[rstest]
#[case("error=5,audit=7", 5, 7)]
#[case("audit=7,error=5", 5, 7)]
#[case("error=5", 5, 2_000)]
#[case("audit=9", 1_000, 9)]
#[case(" error = 3 , audit = 4 ", 3, 4)]
fn budgets_are_read_by_class_name(#[case] text: &str, #[case] error: u32, #[case] audit: u32) {
    assert_eq!(
        ClassBudgets::parse(text).unwrap(),
        ClassBudgets::new(error, audit)
    );
}

#[rstest]
#[case("")]
#[case("error")]
#[case("error=")]
#[case("error=0")]
#[case("error=-1")]
#[case("error=x")]
#[case("allow=5")]
#[case("error=1,error=2")]
#[case("error=1,")]
#[case("error=4294967296")]
fn an_unparsable_budget_list_is_refused(#[case] text: &str) {
    assert_eq!(
        ClassBudgets::parse(text),
        Err(InvalidAccessLogSetting::ClassBudgets)
    );
}

#[rstest]
#[case("1", 1)]
#[case("65536", DEFAULT_CHANNEL_CAPACITY)]
#[case("16777216", 16_777_216)]
fn a_channel_capacity_in_range_is_accepted(#[case] text: &str, #[case] expected: usize) {
    assert_eq!(parse_channel_capacity(text), Ok(expected));
}

#[rstest]
#[case("0")]
#[case("16777217")]
#[case("-1")]
#[case("many")]
#[case("")]
fn a_channel_capacity_out_of_range_is_refused(#[case] text: &str) {
    assert_eq!(
        parse_channel_capacity(text),
        Err(InvalidAccessLogSetting::ChannelCapacity)
    );
}

#[test]
fn every_refusal_names_its_range() {
    for error in [
        InvalidAccessLogSetting::SampleRate,
        InvalidAccessLogSetting::ClassBudgets,
        InvalidAccessLogSetting::ChannelCapacity,
    ] {
        assert!(error.to_string().starts_with("must be"));
    }
}
