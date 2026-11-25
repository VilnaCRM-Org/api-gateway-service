use iam_domain::{
    RouteId, UpstreamName, UpstreamProtocol, UpstreamSettings, UpstreamSettingsDraft,
};
use shared_domain::Uuid;
use tokio::time::Duration;

use super::*;

fn target(name: &str, concurrency_limit: i64) -> UpstreamTarget {
    let settings = UpstreamSettings::new(&UpstreamSettingsDraft {
        namespace: "vilnacrm".to_owned(),
        service_name: format!("{name}-service"),
        catalog_service: name.to_owned(),
        port: 8080,
        protocol: UpstreamProtocol::Http1,
        forward_credentials: false,
        connect_timeout_ms: 250,
        response_timeout_ms: 10_000,
        concurrency_limit,
        retry_budget_percent: 10,
        outlier_threshold: 5,
    })
    .unwrap();
    UpstreamTarget::new(
        UpstreamName::new(name).unwrap(),
        RouteId::from_uuid(Uuid::parse("00000000-0000-0000-0000-000000000001").unwrap()),
    )
    .with_settings(&settings)
}

fn keys(count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("10.0.0.{index}:80"))
        .collect()
}

#[test]
fn a_request_above_the_concurrency_limit_is_refused_at_once() {
    let registry = Registry::new();
    let target = target("user-service", 2);

    let first = registry.admit(&target).unwrap();
    let second = registry.admit(&target).unwrap();

    assert_eq!(
        registry.admit(&target).unwrap_err(),
        ForwardError::Overloaded
    );
    assert_eq!(registry.in_flight("user-service"), 2);
    drop(first);
    assert!(registry.admit(&target).is_ok());
    drop(second);
}

#[test]
fn the_permit_frees_its_place_when_it_drops() {
    let registry = Registry::new();
    let target = target("user-service", 1);

    drop(registry.admit(&target).unwrap());

    assert_eq!(registry.in_flight("user-service"), 0);
    assert!(registry.admit(&target).is_ok());
}

#[test]
fn the_limit_of_one_upstream_does_not_bound_another() {
    let registry = Registry::new();
    let _held = registry.admit(&target("user-service", 1)).unwrap();

    assert!(registry.admit(&target("billing-service", 1)).is_ok());
}

#[test]
fn the_retry_budget_of_an_upstream_follows_its_requests() {
    let registry = Registry::new();
    let target = target("user-service", 10);

    assert!(registry.try_retry(&target));
    assert!(!registry.try_retry(&target));
    for _ in 0..20 {
        registry.count_request(&target);
    }
    assert!(registry.try_retry(&target));
    assert!(!registry.try_retry(&target));
}

#[test]
fn the_retry_budget_of_one_upstream_is_not_spent_by_another() {
    let registry = Registry::new();

    assert!(registry.try_retry(&target("user-service", 10)));
    assert!(registry.try_retry(&target("billing-service", 10)));
}

#[tokio::test(start_paused = true)]
async fn five_failures_in_a_row_eject_an_endpoint_for_ten_seconds() {
    let registry = Registry::new();
    let rule = OutlierRule::for_threshold(5);
    let offered = keys(6);

    for _ in 0..4 {
        assert!(!registry.record_error("10.0.0.0:80", &rule, &offered));
    }
    assert!(registry.record_error("10.0.0.0:80", &rule, &offered));

    assert!(registry.is_ejected("10.0.0.0:80", registry.now_ms()));
    tokio::time::advance(Duration::from_millis(9_999)).await;
    assert!(registry.is_ejected("10.0.0.0:80", registry.now_ms()));
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(!registry.is_ejected("10.0.0.0:80", registry.now_ms()));
}

#[test]
fn with_four_of_six_endpoints_failing_no_more_than_three_are_ejected() {
    let registry = Registry::new();
    let rule = OutlierRule::for_threshold(2);
    let offered = keys(6);

    for key in offered.iter().take(4) {
        registry.record_error(key, &rule, &offered);
        registry.record_error(key, &rule, &offered);
    }

    let now = registry.now_ms();
    let ejected = offered
        .iter()
        .filter(|key| registry.is_ejected(key, now))
        .count();
    assert_eq!(ejected, 3);
}

#[test]
fn a_good_answer_forgets_the_failures_of_an_endpoint_that_is_not_ejected() {
    let registry = Registry::new();
    let rule = OutlierRule::for_threshold(3);
    let offered = keys(4);
    registry.record_error("10.0.0.0:80", &rule, &offered);
    registry.record_error("10.0.0.0:80", &rule, &offered);

    registry.record_success("10.0.0.0:80");

    assert!(!registry.record_error("10.0.0.0:80", &rule, &offered));
    assert!(!registry.record_error("10.0.0.0:80", &rule, &offered));
    assert!(!registry.is_ejected("10.0.0.0:80", registry.now_ms()));
}

#[test]
fn a_late_good_answer_does_not_end_an_ejection() {
    let registry = Registry::new();
    let rule = OutlierRule::for_threshold(1);
    let offered = keys(4);
    assert!(registry.record_error("10.0.0.0:80", &rule, &offered));

    registry.record_success("10.0.0.0:80");

    assert!(registry.is_ejected("10.0.0.0:80", registry.now_ms()));
}

#[test]
fn an_endpoint_that_was_never_seen_is_not_ejected() {
    assert!(!Registry::new().is_ejected("10.0.0.9:80", 0));
}
