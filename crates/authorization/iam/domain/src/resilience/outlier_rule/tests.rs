use rstest::rstest;

use super::*;

#[test]
fn the_rule_of_an_upstream_ejects_for_ten_seconds_up_to_half_of_the_endpoints() {
    let rule = OutlierRule::for_threshold(5);

    assert_eq!(rule.ejection_ms(), 10_000);
    assert!(!rule.trips(4));
    assert!(rule.trips(5));
    assert!(rule.trips(6));
}

#[test]
fn a_threshold_of_zero_counts_as_one() {
    assert!(OutlierRule::for_threshold(0).trips(1));
}

#[rstest]
#[case::lone_endpoint(0, 1, false)]
#[case::two_endpoints_first(0, 2, true)]
#[case::two_endpoints_second(1, 2, false)]
#[case::six_endpoints_third(2, 6, true)]
#[case::six_endpoints_fourth(3, 6, false)]
#[case::five_endpoints_second(1, 5, true)]
#[case::five_endpoints_third(2, 5, false)]
#[case::nothing_offered(0, 0, false)]
fn at_most_half_of_the_endpoints_are_ejected(
    #[case] ejected: usize,
    #[case] total: usize,
    #[case] allowed: bool,
) {
    assert_eq!(
        OutlierRule::for_threshold(5).may_eject(ejected, total),
        allowed
    );
}

#[test]
fn a_cap_of_a_hundred_percent_ejects_every_endpoint() {
    let rule = OutlierRule::new(5, 1_000, 100);

    assert!(rule.may_eject(2, 3));
    assert!(!rule.may_eject(3, 3));
}

#[test]
fn a_cap_above_a_hundred_percent_counts_as_a_hundred() {
    assert!(!OutlierRule::new(5, 1_000, 200).may_eject(3, 3));
}

#[test]
fn five_failures_in_a_row_eject_the_endpoint_for_ten_seconds() {
    let rule = OutlierRule::for_threshold(5);
    let mut health = EndpointHealth::default();

    for _ in 0..4 {
        assert!(!health.record_error(&rule, 1_000, true));
    }
    assert!(!health.is_ejected(1_000));
    assert!(health.record_error(&rule, 1_000, true));

    assert!(health.is_ejected(1_000));
    assert!(health.is_ejected(10_999));
    assert!(!health.is_ejected(11_000));
}

#[test]
fn a_good_answer_ends_the_run_of_failures() {
    let rule = OutlierRule::for_threshold(3);
    let mut health = EndpointHealth::default();
    health.record_error(&rule, 0, true);
    health.record_error(&rule, 0, true);

    health.record_success();

    assert_eq!(health.consecutive_errors(), 0);
    assert!(!health.record_error(&rule, 0, true));
    assert!(!health.is_ejected(0));
}

#[test]
fn the_cap_keeps_an_endpoint_in_while_it_keeps_failing() {
    let rule = OutlierRule::for_threshold(2);
    let mut health = EndpointHealth::default();

    for _ in 0..6 {
        assert!(!health.record_error(&rule, 0, false));
    }

    assert!(!health.is_ejected(0));
    assert_eq!(health.consecutive_errors(), 6);
    assert!(health.record_error(&rule, 0, true));
}

#[test]
fn an_endpoint_whose_ejection_ran_out_starts_a_new_count() {
    let rule = OutlierRule::for_threshold(2);
    let mut health = EndpointHealth::default();
    health.record_error(&rule, 0, true);
    assert!(health.record_error(&rule, 0, true));

    assert!(!health.record_error(&rule, 10_000, true));
    assert!(!health.is_ejected(10_000));
    assert!(health.record_error(&rule, 10_000, true));
    assert!(health.is_ejected(10_001));
}

#[test]
fn a_failure_while_ejected_does_not_extend_the_ejection() {
    let rule = OutlierRule::for_threshold(1);
    let mut health = EndpointHealth::default();
    assert!(health.record_error(&rule, 0, true));

    assert!(!health.record_error(&rule, 5_000, true));

    assert!(!health.is_ejected(10_000));
}
