use std::sync::atomic::{AtomicU64, Ordering};

use super::{Candidate, DEFAULT_SPILL_THRESHOLD, EndpointSelector};
use crate::endpoint::zone::Zone;
use crate::endpoint::{Condition, EndpointConditions, EndpointParts, UpstreamEndpoint};
use crate::port::rng::Rng;

mod properties;

/// A reproducible generator: the same seed gives the same draws.
#[derive(Debug)]
pub(super) struct SeededDraws(AtomicU64);

impl SeededDraws {
    pub(super) const fn new(seed: u64) -> Self {
        Self(AtomicU64::new(seed))
    }
}

impl Rng for SeededDraws {
    fn next_u64(&self) -> u64 {
        let state = self
            .0
            .fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed)
            .wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mixed = (state ^ state.rotate_right(30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        let mixed = (mixed ^ mixed.rotate_right(27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ mixed.rotate_right(31)
    }
}

pub(super) fn zone(name: &str) -> Zone {
    Zone::new(name).unwrap()
}

pub(super) fn endpoint(
    address: &str,
    zone_name: &str,
    conditions: EndpointConditions,
) -> UpstreamEndpoint {
    UpstreamEndpoint::new(EndpointParts {
        address: address.to_owned(),
        port: 8081,
        zone: Some(zone(zone_name)),
        pod: None,
        conditions,
    })
}

fn healthy(address: &str, zone_name: &str) -> UpstreamEndpoint {
    endpoint(address, zone_name, EndpointConditions::healthy())
}

fn selector() -> EndpointSelector {
    EndpointSelector::new(Some(zone("a")), true, DEFAULT_SPILL_THRESHOLD)
}

fn candidates<'a>(endpoints: &'a [UpstreamEndpoint], in_flight: &[u32]) -> Vec<Candidate<'a>> {
    endpoints
        .iter()
        .zip(in_flight)
        .map(|(endpoint, &in_flight)| Candidate {
            endpoint,
            in_flight,
        })
        .collect()
}

#[test]
fn nothing_is_selected_without_candidates() {
    assert_eq!(selector().select(&[], &SeededDraws::new(1)), None);
}

#[test]
fn nothing_is_selected_when_no_candidate_is_offered() {
    let endpoints = [
        endpoint("10.0.0.1", "a", EndpointConditions::default()),
        endpoint(
            "10.0.0.2",
            "a",
            EndpointConditions::healthy().with(Condition::Terminating, true),
        ),
    ];

    let chosen = selector().select(&candidates(&endpoints, &[0, 0]), &SeededDraws::new(1));

    assert_eq!(chosen, None);
}

#[test]
fn the_endpoint_with_fewer_requests_in_flight_wins_between_two_candidates() {
    let endpoints = [healthy("10.0.0.1", "a"), healthy("10.0.0.2", "a")];

    for seed in 0..50 {
        let chosen = selector().select(&candidates(&endpoints, &[9, 3]), &SeededDraws::new(seed));
        assert_eq!(chosen, Some(1), "seed {seed}");
        let chosen = selector().select(&candidates(&endpoints, &[3, 9]), &SeededDraws::new(seed));
        assert_eq!(chosen, Some(0), "seed {seed}");
    }
}

#[test]
fn a_single_offered_endpoint_is_always_selected() {
    let endpoints = [
        endpoint("10.0.0.1", "a", EndpointConditions::default()),
        healthy("10.0.0.2", "a"),
    ];

    let chosen = selector().select(&candidates(&endpoints, &[0, 500]), &SeededDraws::new(7));

    assert_eq!(chosen, Some(1));
}

#[test]
fn a_ready_own_zone_endpoint_beats_a_lighter_endpoint_of_another_zone() {
    let endpoints = [healthy("10.0.0.1", "b"), healthy("10.0.0.2", "a")];

    for seed in 0..50 {
        let chosen = selector().select(&candidates(&endpoints, &[0, 10]), &SeededDraws::new(seed));
        assert_eq!(chosen, Some(1), "seed {seed}");
    }
}

#[test]
fn requests_go_to_other_zones_when_the_own_zone_has_no_healthy_endpoint() {
    let endpoints = [
        endpoint("10.0.0.1", "a", EndpointConditions::default()),
        healthy("10.0.0.2", "b"),
        healthy("10.0.0.3", "c"),
    ];

    for seed in 0..50 {
        let chosen =
            selector().select(&candidates(&endpoints, &[0, 4, 4]), &SeededDraws::new(seed));
        assert!(matches!(chosen, Some(1 | 2)), "seed {seed}: {chosen:?}");
    }
}

#[test]
fn requests_spill_when_the_load_per_own_zone_endpoint_exceeds_the_threshold() {
    let endpoints = [
        healthy("10.0.0.1", "a"),
        healthy("10.0.0.2", "a"),
        healthy("10.0.0.3", "b"),
    ];
    let at_threshold = DEFAULT_SPILL_THRESHOLD.saturating_mul(2);
    let over_threshold = at_threshold.saturating_add(2);

    let at = selector().select(
        &candidates(&endpoints, &[at_threshold, 0, 0]),
        &SeededDraws::new(3),
    );
    assert!(matches!(at, Some(0 | 1)));
    for seed in 0..20 {
        let over = selector().select(
            &candidates(&endpoints, &[over_threshold, 0, 0]),
            &SeededDraws::new(seed),
        );
        assert_eq!(over, Some(2), "seed {seed}");
    }
}

#[test]
fn an_overloaded_own_zone_keeps_the_requests_when_no_other_zone_has_a_healthy_endpoint() {
    let endpoints = [
        healthy("10.0.0.1", "a"),
        endpoint("10.0.0.2", "b", EndpointConditions::default()),
    ];

    let chosen = selector().select(&candidates(&endpoints, &[10_000, 0]), &SeededDraws::new(5));

    assert_eq!(chosen, Some(0));
}

#[test]
fn switching_the_zone_preference_off_pools_every_offered_endpoint() {
    let endpoints = [healthy("10.0.0.1", "a"), healthy("10.0.0.2", "b")];
    let selector = EndpointSelector::new(Some(zone("a")), false, DEFAULT_SPILL_THRESHOLD);

    let crossed = (0..100).any(|seed| {
        selector.select(&candidates(&endpoints, &[0, 0]), &SeededDraws::new(seed)) == Some(1)
    });

    assert!(crossed);
}

#[test]
fn a_gateway_without_a_zone_pools_every_offered_endpoint() {
    let endpoints = [healthy("10.0.0.1", "a"), healthy("10.0.0.2", "b")];
    let selector = EndpointSelector::new(None, true, DEFAULT_SPILL_THRESHOLD);

    let chosen = (0..100)
        .filter_map(|seed| {
            selector.select(&candidates(&endpoints, &[0, 0]), &SeededDraws::new(seed))
        })
        .collect::<Vec<_>>();

    assert!(chosen.contains(&0) && chosen.contains(&1));
}

#[test]
fn an_endpoint_without_a_zone_counts_as_another_zone() {
    let unzoned = UpstreamEndpoint::new(EndpointParts {
        address: "10.0.0.9".to_owned(),
        port: 80,
        zone: None,
        pod: None,
        conditions: EndpointConditions::healthy(),
    });
    let endpoints = [unzoned, healthy("10.0.0.2", "a")];

    for seed in 0..20 {
        let chosen = selector().select(&candidates(&endpoints, &[0, 1]), &SeededDraws::new(seed));
        assert_eq!(chosen, Some(1));
    }
}

#[test]
fn the_same_seed_replays_the_same_selections() {
    let endpoints = [
        healthy("10.0.0.1", "a"),
        healthy("10.0.0.2", "a"),
        healthy("10.0.0.3", "a"),
    ];
    let run = |seed| {
        let draws = SeededDraws::new(seed);
        (0..50)
            .map(|_| selector().select(&candidates(&endpoints, &[5, 5, 5]), &draws))
            .collect::<Vec<_>>()
    };

    assert_eq!(run(11), run(11));
}
