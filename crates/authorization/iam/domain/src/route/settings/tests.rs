use rstest::rstest;

use super::{BodyLimit, EnforcementMode, RetryPolicy, RouteFlag, RouteFlags, RouteTimeouts};
use crate::error::InvalidRoute;

#[test]
fn flags_are_off_by_default_and_switch_independently() {
    let flags = RouteFlags::default();

    assert!(!flags.graphql() && !flags.streaming() && !flags.anonymous());

    let flags = flags
        .with(RouteFlag::Anonymous, true)
        .with(RouteFlag::Graphql, true);
    assert!(flags.graphql() && flags.anonymous() && !flags.streaming());

    let flags = flags
        .with(RouteFlag::Anonymous, false)
        .with(RouteFlag::Streaming, true);
    assert!(flags.graphql() && flags.streaming() && !flags.anonymous());
    assert!(flags.has(RouteFlag::Streaming));
}

#[rstest]
#[case(RouteFlag::Graphql, "graphql")]
#[case(RouteFlag::Streaming, "streaming")]
#[case(RouteFlag::Anonymous, "anonymous")]
fn flags_have_names(#[case] flag: RouteFlag, #[case] name: &str) {
    assert_eq!(flag.as_str(), name);
}

#[test]
fn modes_and_policies_have_names() {
    assert_eq!(EnforcementMode::Enforce.as_str(), "enforce");
    assert_eq!(EnforcementMode::Audit.as_str(), "audit");
    assert_eq!(RetryPolicy::None.as_str(), "none");
    assert_eq!(RetryPolicy::Idempotent.as_str(), "idempotent");
}

#[test]
fn a_body_limit_is_at_least_one_byte() {
    assert_eq!(BodyLimit::new(1).unwrap().bytes(), 1);
    assert_eq!(BodyLimit::new(0), Err(InvalidRoute::BodyLimitRange));
    assert_eq!(BodyLimit::new(-5), Err(InvalidRoute::BodyLimitRange));
}

#[test]
fn timeouts_are_positive_and_fit_32_bits() {
    let timeouts = RouteTimeouts::new(30_000, 60_000).unwrap();

    assert_eq!(timeouts.request_ms(), 30_000);
    assert_eq!(timeouts.idle_ms(), 60_000);
}

#[rstest]
#[case(0, 1, vec![InvalidRoute::RequestTimeoutRange])]
#[case(1, -1, vec![InvalidRoute::IdleTimeoutRange])]
#[case(0, 4_294_967_296, vec![InvalidRoute::RequestTimeoutRange, InvalidRoute::IdleTimeoutRange])]
fn invalid_timeouts_report_each_violation(
    #[case] request: i64,
    #[case] idle: i64,
    #[case] expected: Vec<InvalidRoute>,
) {
    assert_eq!(RouteTimeouts::new(request, idle), Err(expected));
}

#[test]
fn the_printed_enforcement_mode_and_retry_policy_parse_back() {
    for mode in [EnforcementMode::Enforce, EnforcementMode::Audit] {
        assert_eq!(EnforcementMode::parse(mode.as_str()), Some(mode));
    }
    for retry in [RetryPolicy::None, RetryPolicy::Idempotent] {
        assert_eq!(RetryPolicy::parse(retry.as_str()), Some(retry));
    }
    assert_eq!(EnforcementMode::parse("Enforce"), None);
    assert_eq!(RetryPolicy::parse("always"), None);
}
