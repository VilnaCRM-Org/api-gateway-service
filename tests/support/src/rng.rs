//! Randomness double.

use std::sync::{Mutex, PoisonError};

use rand::Rng as _;
use rand::SeedableRng as _;
use rand::rngs::StdRng;

use crate::seed::TestRng;

/// A seeded, reproducible implementation of the randomness port: two instances with the same seed
/// yield the same sequence.
#[derive(Debug)]
pub struct FakeRng(Mutex<StdRng>);

impl FakeRng {
    /// A generator seeded from `TEST_SEED`, so every failure replays with the printed seed.
    ///
    /// # Panics
    ///
    /// Panics like [`TestRng::from_env`] when `TEST_SEED` is unset or invalid.
    #[must_use]
    pub fn new() -> Self {
        Self::seeded(TestRng::from_env().seed())
    }

    /// A generator with a known seed.
    #[must_use]
    pub fn seeded(seed: u64) -> Self {
        Self(Mutex::new(StdRng::seed_from_u64(seed)))
    }
}

impl Default for FakeRng {
    fn default() -> Self {
        Self::new()
    }
}

impl iam_domain::Rng for FakeRng {
    fn next_u64(&self) -> u64 {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .next_u64()
    }
}

#[cfg(test)]
mod tests;
