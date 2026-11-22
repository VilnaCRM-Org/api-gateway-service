//! Randomness port.

/// Source of every random draw (power-of-two choices, jitter, peer and log sampling); tests seed it.
pub trait Rng: std::fmt::Debug + Send + Sync {
    /// The next uniformly distributed 64-bit value.
    fn next_u64(&self) -> u64;
}
