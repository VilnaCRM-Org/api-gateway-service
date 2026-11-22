//! Request digester double.

use iam_domain::{RequestDigest, RequestDigester};

/// A digester that is deterministic and spreads the bytes of the text over 32 bytes, without being
/// a hash: equal texts give equal digests and different texts almost always give different ones.
#[derive(Debug, Default, Clone, Copy)]
pub struct FakeRequestDigester;

impl RequestDigester for FakeRequestDigester {
    fn digest(&self, canonical: &str) -> RequestDigest {
        let mut bytes = [0_u8; RequestDigest::LENGTH];
        for (slot, byte) in (0..RequestDigest::LENGTH).cycle().zip(canonical.bytes()) {
            if let Some(cell) = bytes.get_mut(slot) {
                *cell = cell.rotate_left(3) ^ byte;
            }
        }
        RequestDigest::from_bytes(bytes)
    }
}

#[cfg(test)]
mod tests;
