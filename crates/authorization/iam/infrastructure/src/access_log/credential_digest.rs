//! The credential digest prefix of an access record.

use iam_domain::Credential;
use sha2::{Digest as _, Sha256};

/// The number of digest bytes that make the 8 hexadecimal characters of the prefix.
const PREFIX_BYTES: usize = 4;

/// The first 8 hexadecimal characters of the SHA-256 digest of the credential.
///
/// They let an investigator tell two credentials apart without the log holding either of them;
/// `None` for a request without a credential.
#[must_use]
pub fn credential_digest_prefix(credential: &Credential) -> Option<String> {
    if credential.is_blank() {
        return None;
    }
    let digest = Sha256::digest(credential.expose().as_bytes());
    Some(
        digest
            .iter()
            .take(PREFIX_BYTES)
            .flat_map(|byte| [byte >> 4, byte & 0x0f])
            .filter_map(|nibble| char::from_digit(u32::from(nibble), 16))
            .collect(),
    )
}

#[cfg(test)]
mod tests;
