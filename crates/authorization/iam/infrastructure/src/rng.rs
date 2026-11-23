//! The seeded implementation of the randomness port.

use std::sync::{Mutex, PoisonError};

use iam_domain::Rng;
use rand::rngs::StdRng;
use rand::{Rng as _, SeedableRng as _};

/// Draws from a cryptographically strong generator that is seeded once.
///
/// [`SeededRng::from_os`] seeds it from the operating system (production); [`SeededRng::from_seed`]
/// takes a fixed seed, so a test replays the draws of a failed run.
pub struct SeededRng {
    generator: Mutex<StdRng>,
}

impl SeededRng {
    /// A generator seeded from the operating system.
    #[must_use]
    pub fn from_os() -> Self {
        Self::with(StdRng::from_rng(&mut rand::rng()))
    }

    /// A generator whose draws are the same for the same `seed`.
    #[must_use]
    pub fn from_seed(seed: u64) -> Self {
        Self::with(StdRng::seed_from_u64(seed))
    }

    const fn with(generator: StdRng) -> Self {
        Self {
            generator: Mutex::new(generator),
        }
    }
}

impl std::fmt::Debug for SeededRng {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SeededRng").finish_non_exhaustive()
    }
}

impl Rng for SeededRng {
    fn next_u64(&self) -> u64 {
        self.generator
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .next_u64()
    }
}

#[cfg(test)]
mod tests;
