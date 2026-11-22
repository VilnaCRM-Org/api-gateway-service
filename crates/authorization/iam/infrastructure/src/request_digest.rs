//! SHA-256 implementation of the request digester port.

use iam_domain::{RequestDigest, RequestDigester};
use sha2::{Digest as _, Sha256};

/// Digests the canonical request of an idempotent write with SHA-256.
///
/// The digest depends on the text alone, so a replay that lands on another pod, or in a later
/// release, within the 24 hours of the idempotency record finds the same digest.
#[derive(Debug, Default, Clone, Copy)]
pub struct Sha256RequestDigester;

impl RequestDigester for Sha256RequestDigester {
    fn digest(&self, canonical: &str) -> RequestDigest {
        RequestDigest::from_bytes(Sha256::digest(canonical.as_bytes()).into())
    }
}

#[cfg(test)]
mod tests;
