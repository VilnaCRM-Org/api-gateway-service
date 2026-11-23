//! Property tests of the zone preference (NFR-43). Failures replay from `PROPTEST_RNG_SEED`.

use proptest::collection::vec;
use proptest::prelude::*;

use super::{Candidate, DEFAULT_SPILL_THRESHOLD, EndpointSelector, SeededDraws, endpoint, zone};
use crate::endpoint::EndpointConditions;

/// The selections one case draws.
const DRAWS: usize = 100_000;

/// The most requests per endpoint that the own zone may carry in these cases: below the threshold.
const MAX_LOAD: u32 = DEFAULT_SPILL_THRESHOLD;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    #[test]
    fn no_selection_crosses_zones_while_the_own_zone_is_healthy_and_below_the_threshold(
        seed in any::<u64>(),
        own_loads in vec(0..=MAX_LOAD, 1..5),
        other_loads in vec(0..=10_000_u32, 1..5),
    ) {
        let own: Vec<_> = (0..own_loads.len())
            .map(|index| endpoint(&format!("10.0.0.{index}"), "a", EndpointConditions::healthy()))
            .collect();
        let others: Vec<_> = (0..other_loads.len())
            .map(|index| endpoint(&format!("10.0.1.{index}"), "b", EndpointConditions::healthy()))
            .collect();
        let candidates: Vec<_> = own
            .iter()
            .zip(&own_loads)
            .chain(others.iter().zip(&other_loads))
            .map(|(endpoint, &in_flight)| Candidate { endpoint, in_flight })
            .collect();
        let selector = EndpointSelector::new(Some(zone("a")), true, DEFAULT_SPILL_THRESHOLD);
        let draws = SeededDraws::new(seed);

        let crossed = (0..DRAWS)
            .filter_map(|_| selector.select(&candidates, &draws))
            .filter(|&index| index >= own.len())
            .count();

        prop_assert!(crossed <= DRAWS / 20, "cross-zone share above 5%: {crossed}");
        prop_assert_eq!(crossed, 0);
    }
}
