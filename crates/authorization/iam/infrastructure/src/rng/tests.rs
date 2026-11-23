use iam_domain::Rng as _;

use super::SeededRng;

fn draws(rng: &SeededRng, count: usize) -> Vec<u64> {
    (0..count).map(|_draw| rng.next_u64()).collect()
}

#[test]
fn the_same_seed_gives_the_same_draws() {
    let first = SeededRng::from_seed(7);
    let second = SeededRng::from_seed(7);

    assert_eq!(draws(&first, 16), draws(&second, 16));
}

#[test]
fn different_seeds_give_different_draws() {
    let first = SeededRng::from_seed(7);
    let second = SeededRng::from_seed(8);

    assert_ne!(draws(&first, 16), draws(&second, 16));
}

#[test]
fn successive_draws_differ() {
    let rng = SeededRng::from_seed(7);

    let drawn = draws(&rng, 16);

    let mut unique = drawn.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), drawn.len());
}

#[test]
fn two_operating_system_seeds_differ() {
    let first = SeededRng::from_os();
    let second = SeededRng::from_os();

    assert_ne!(draws(&first, 4), draws(&second, 4));
}

#[test]
fn the_debug_output_hides_the_generator_state() {
    let rng = SeededRng::from_seed(7);

    assert_eq!(format!("{rng:?}"), "SeededRng { .. }");
}
