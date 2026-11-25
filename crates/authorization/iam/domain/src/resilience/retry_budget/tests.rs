use super::*;

fn after_requests(percent: u8, requests: u64) -> RetryBudget {
    let mut budget = RetryBudget::new(percent);
    for _ in 0..requests {
        budget.record_request();
    }
    budget
}

#[test]
fn a_budget_with_no_requests_still_allows_the_floor() {
    let mut budget = RetryBudget::new(10);

    assert!(budget.try_retry());
    assert!(!budget.try_retry());
}

#[test]
fn the_boundary_is_ten_percent_of_the_requests() {
    let mut budget = after_requests(10, 19);
    assert!(budget.try_retry());
    assert!(!budget.allows_retry());

    budget.record_request();
    assert!(budget.try_retry());
    assert_eq!(budget.retries(), 2);
    assert!(!budget.allows_retry());
}

#[test]
fn retries_above_the_share_are_refused() {
    let mut budget = after_requests(10, 100);

    let granted = (0..20).filter(|_| budget.try_retry()).count();

    assert_eq!(granted, 10);
    assert!(!budget.try_retry());
}

#[test]
fn a_budget_of_zero_allows_nothing() {
    let mut budget = after_requests(0, 500);

    assert!(!budget.allows_retry());
    assert!(!budget.try_retry());
    assert_eq!(budget.retries(), 0);
}

#[test]
fn a_budget_above_a_hundred_percent_counts_as_a_hundred() {
    let mut budget = after_requests(250, 3);

    assert!(budget.try_retry());
    assert!(budget.try_retry());
    assert!(budget.try_retry());
    assert!(!budget.try_retry());
}

#[test]
fn the_counters_are_halved_when_the_window_is_full() {
    let mut budget = after_requests(10, BUDGET_WINDOW_REQUESTS);
    for _ in 0..100 {
        assert!(budget.try_retry());
    }
    assert_eq!(budget.requests(), BUDGET_WINDOW_REQUESTS);

    budget.record_request();

    assert_eq!(budget.requests(), BUDGET_WINDOW_REQUESTS.div_ceil(2));
    assert_eq!(budget.retries(), 50);
}

#[test]
fn another_percent_keeps_the_counters() {
    let budget = after_requests(10, 40).with_percent(50);

    assert_eq!(budget.requests(), 40);
    assert!(budget.allows_retry());
    assert!(!budget.with_percent(0).allows_retry());
}
