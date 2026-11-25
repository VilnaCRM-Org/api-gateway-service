use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use iam_domain::Rng;

use super::{Edge, EdgeLimits, jitter_age, retire_early};

#[derive(Debug)]
struct Fixed(u64);

impl Rng for Fixed {
    fn next_u64(&self) -> u64 {
        self.0
    }
}

fn ip(last: u8) -> IpAddr {
    IpAddr::from([192, 0, 2, last])
}

#[test]
fn the_default_limits_are_the_numbers_of_the_story() {
    let limits = EdgeLimits::default();

    assert_eq!(limits.header_block, 16 * 1024);
    assert_eq!(limits.header_read_timeout, Duration::from_secs(10));
    assert_eq!(limits.max_concurrent_streams, 128);
    assert_eq!(limits.max_header_list_size, 16 * 1024);
    assert_eq!(limits.buffered_per_connection, 256 * 1024);
    assert_eq!(limits.connections_per_ip, 64);
    assert_eq!(limits.connections_per_subject, 32);
    assert_eq!(limits.keep_alive_idle, Duration::from_secs(120));
    assert_eq!(limits.connection_age, Duration::from_secs(600));
    assert_eq!(limits.early_rate, 2000);
    assert_eq!(limits.early_rate_after, Duration::from_secs(120));
    assert_eq!(limits.early_requests, 100_000);
}

#[test]
fn the_age_stays_within_twenty_percent_of_ten_minutes() {
    let base = Duration::from_secs(600);

    assert_eq!(jitter_age(base, 20, 0), Duration::from_secs(480));
    assert_eq!(jitter_age(base, 20, 240_000), Duration::from_mins(12));
    assert_eq!(jitter_age(base, 20, 120_000), Duration::from_secs(600));
    for draw in [1, 7, 99_999, u64::MAX, u64::MAX - 1] {
        let age = jitter_age(base, 20, draw);
        assert!(age >= Duration::from_secs(480) && age <= Duration::from_mins(12));
    }
}

#[test]
fn a_zero_jitter_is_the_base_age() {
    assert_eq!(
        jitter_age(Duration::from_secs(600), 0, u64::MAX),
        Duration::from_secs(600)
    );
}

#[test]
fn the_edge_draws_the_age_through_the_rng_and_without_one_uses_the_base() {
    let jittered = Edge::new(EdgeLimits::default(), false, Some(Arc::new(Fixed(0))));
    let plain = Edge::new(EdgeLimits::default(), false, None);

    assert_eq!(jittered.connection_age(), Duration::from_secs(480));
    assert_eq!(plain.connection_age(), Duration::from_secs(600));
}

#[test]
fn a_connection_with_too_many_requests_retires_at_once() {
    let limits = EdgeLimits::default();

    assert!(!retire_early(&limits, Duration::from_secs(1), 99_999));
    assert!(retire_early(&limits, Duration::from_secs(1), 100_000));
}

#[test]
fn a_fast_connection_retires_only_after_two_minutes() {
    let limits = EdgeLimits {
        early_requests: u64::MAX,
        ..EdgeLimits::default()
    };
    let busy = 2001 * 119;

    assert!(!retire_early(&limits, Duration::from_secs(119), busy));
    assert!(retire_early(&limits, Duration::from_secs(120), 2001 * 120));
    assert!(!retire_early(&limits, Duration::from_secs(120), 2000 * 120));
}

#[test]
fn a_connection_with_no_age_does_not_divide_by_zero() {
    let limits = EdgeLimits {
        early_rate_after: Duration::ZERO,
        ..EdgeLimits::default()
    };

    assert!(!retire_early(&limits, Duration::ZERO, 5));
}

#[test]
fn the_sixty_fifth_connection_of_an_address_is_refused_and_a_closed_one_frees_a_slot() {
    let edge = Edge::new(EdgeLimits::default(), false, None);
    let mut held: Vec<_> = (0..64).map(|_| edge.admit(ip(1)).unwrap()).collect();

    assert_eq!(held.len(), 64);
    assert!(edge.admit(ip(1)).is_none());
    assert!(edge.admit(ip(2)).is_some());
    held.pop();
    assert!(edge.admit(ip(1)).is_some());
}

#[test]
fn the_thirty_third_connection_of_a_subject_is_refused() {
    let edge = Edge::new(EdgeLimits::default(), false, None);
    let connections: Vec<_> = (0..32).map(|_| edge.claims()).collect();
    for connection in &connections {
        assert!(connection.claim("subject-1"));
    }
    let thirty_third = edge.claims();

    assert!(!thirty_third.claim("subject-1"));
    assert!(thirty_third.claim("subject-2"));
    assert_eq!(thirty_third.held(), 1);
}

#[test]
fn a_connection_that_repeats_a_subject_holds_one_slot_and_frees_it_when_dropped() {
    let edge = Edge::new(
        EdgeLimits {
            connections_per_subject: 1,
            ..EdgeLimits::default()
        },
        false,
        None,
    );
    let first = edge.claims();
    assert!(first.claim("subject"));
    assert!(first.claim("subject"));
    assert_eq!(first.held(), 1);

    let second = edge.claims();
    assert!(!second.claim("subject"));
    drop(first);
    assert!(second.claim("subject"));
}

#[test]
fn the_proxy_header_is_read_by_the_server_only_when_asked_and_enabled() {
    let off = Edge::new(EdgeLimits::default(), false, None).reading_header_in_serve(true);
    let tls = Edge::new(EdgeLimits::default(), true, None);
    let plain = Edge::new(EdgeLimits::default(), true, None).reading_header_in_serve(true);

    assert!(!off.header_in_serve() && !off.proxy_protocol());
    assert!(tls.proxy_protocol() && !tls.header_in_serve());
    assert!(plain.header_in_serve());
    assert_eq!(plain.limits(), &EdgeLimits::default());
}

#[tokio::test(start_paused = true)]
async fn a_connection_ends_at_its_age() {
    let edge = Edge::new(EdgeLimits::default(), false, None);
    let requests = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&requests);
    let task =
        tokio::spawn(async move { edge.retire(move || counter.load(Ordering::Relaxed)).await });

    tokio::time::sleep(Duration::from_secs(599)).await;
    assert!(!task.is_finished());
    tokio::time::sleep(Duration::from_secs(2)).await;

    assert!(task.is_finished());
}

#[tokio::test(start_paused = true)]
async fn a_connection_ends_early_when_it_carries_too_many_requests() {
    let edge = Edge::new(EdgeLimits::default(), false, None);
    let requests = AtomicU64::new(0);

    let started = tokio::time::Instant::now();
    tokio::join!(edge.retire(|| requests.load(Ordering::Relaxed)), async {
        tokio::time::sleep(Duration::from_secs(3)).await;
        requests.store(100_000, Ordering::Relaxed);
    });

    assert!(started.elapsed() < Duration::from_secs(10));
}
