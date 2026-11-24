use iam_domain::{EndpointConditions, EndpointParts, UpstreamEndpoint, Zone};
use test_support::rng::FakeRng;

use super::{FULL_FLEET_BELOW, OWN_ZONE_SAMPLE, SAMPLE_SIZE, select_peers};

fn zone(name: &str) -> Zone {
    Zone::new(name).unwrap()
}

fn peer(index: usize, zone_name: &str) -> UpstreamEndpoint {
    UpstreamEndpoint::new(EndpointParts {
        address: format!("10.0.0.{index}"),
        port: 9090,
        zone: Some(zone(zone_name)),
        pod: Some(format!("gateway-{index}")),
        conditions: EndpointConditions::healthy(),
    })
}

/// `own` peers in zone `a`, then `others` peers spread over zones `b` and `c`.
fn fleet(own: usize, others: usize) -> Vec<UpstreamEndpoint> {
    let mut peers: Vec<_> = (0..own).map(|index| peer(index, "a")).collect();
    for index in 0..others {
        let name = if index % 2 == 0 { "b" } else { "c" };
        peers.push(peer(own.saturating_add(index), name));
    }
    peers
}

fn in_zone(sample: &[UpstreamEndpoint], name: &str) -> usize {
    let wanted = zone(name);
    sample
        .iter()
        .filter(|peer| peer.zone() == Some(&wanted))
        .count()
}

#[test]
fn a_fleet_below_ten_pods_is_asked_entirely() {
    let rng = FakeRng::seeded(7);

    let sample = select_peers(&rng, fleet(2, 4), Some(&zone("a")));

    assert_eq!(sample.len(), 6);
}

#[test]
fn nine_peers_and_the_pod_make_a_fleet_that_is_sampled() {
    let rng = FakeRng::seeded(7);

    let eight = select_peers(&rng, fleet(3, 5), Some(&zone("a")));
    let nine = select_peers(&rng, fleet(3, 6), Some(&zone("a")));

    assert_eq!(eight.len(), 8);
    assert_eq!(nine.len(), SAMPLE_SIZE);
    assert_eq!(FULL_FLEET_BELOW, 10);
}

#[test]
fn a_fleet_of_twelve_peers_is_sampled_to_five_with_three_in_the_own_zone() {
    for seed in 0..32 {
        let rng = FakeRng::seeded(seed);

        let sample = select_peers(&rng, fleet(4, 8), Some(&zone("a")));

        assert_eq!(sample.len(), SAMPLE_SIZE, "seed {seed}");
        assert_eq!(in_zone(&sample, "a"), OWN_ZONE_SAMPLE, "seed {seed}");
    }
}

#[test]
fn the_sample_is_completed_from_the_other_zones_when_the_own_zone_has_few_peers() {
    let rng = FakeRng::seeded(3);

    let sample = select_peers(&rng, fleet(1, 11), Some(&zone("a")));

    assert_eq!(sample.len(), SAMPLE_SIZE);
    assert_eq!(in_zone(&sample, "a"), 1);
}

#[test]
fn the_sample_is_completed_from_the_own_zone_when_the_other_zones_have_few_peers() {
    let rng = FakeRng::seeded(3);

    let sample = select_peers(&rng, fleet(10, 1), Some(&zone("a")));

    assert_eq!(sample.len(), SAMPLE_SIZE);
    assert_eq!(in_zone(&sample, "a"), 4);
}

#[test]
fn a_fleet_with_fewer_peers_than_the_sample_gives_every_peer() {
    let rng = FakeRng::seeded(3);

    assert_eq!(
        select_peers(&rng, Vec::new(), Some(&zone("a"))),
        Vec::<UpstreamEndpoint>::new()
    );
}

#[test]
fn the_same_seed_draws_the_same_sample_and_another_seed_draws_another() {
    let draw = |seed| {
        select_peers(&FakeRng::seeded(seed), fleet(6, 6), Some(&zone("a")))
            .iter()
            .map(|peer| peer.address().to_owned())
            .collect::<Vec<_>>()
    };

    assert_eq!(draw(11), draw(11));
    assert!((12..40).any(|seed| draw(seed) != draw(11)));
}

#[test]
fn a_pod_of_an_unknown_zone_samples_only_peers_without_a_zone_as_its_own() {
    let rng = FakeRng::seeded(5);

    let sample = select_peers(&rng, fleet(6, 6), None);

    assert_eq!(sample.len(), SAMPLE_SIZE);
}
