use iam_domain::Rng;

use super::FakeRng;
use crate::seed::TestRng;

fn draws(rng: &dyn Rng, count: usize) -> Vec<u64> {
    (0..count).map(|_| rng.next_u64()).collect()
}

#[test]
fn two_generators_with_the_same_seed_yield_the_same_sequence() {
    let seed = TestRng::from_env().seed();

    assert_eq!(
        draws(&FakeRng::seeded(seed), 32),
        draws(&FakeRng::seeded(seed), 32)
    );
}

#[test]
fn the_default_generator_uses_the_test_seed() {
    let seed = TestRng::from_env().seed();

    assert_eq!(
        draws(&FakeRng::new(), 16),
        draws(&FakeRng::seeded(seed), 16)
    );
}

#[test]
fn different_seeds_yield_different_sequences() {
    assert_ne!(draws(&FakeRng::seeded(1), 8), draws(&FakeRng::seeded(2), 8));
}

#[test]
fn a_sequence_is_not_constant() {
    let sequence = draws(&FakeRng::seeded(7), 8);

    assert!(sequence.windows(2).any(|pair| pair[0] != pair[1]));
}
