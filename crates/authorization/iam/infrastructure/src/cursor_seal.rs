//! The HMAC adapter of the cursor seal (Story 14.3, NFR-44).
//!
//! A token is `base64url(payload || tag)` with the tag the HMAC-SHA256 of the payload under the key
//! of the adapter. A token whose tag does not verify, because the payload was altered, the token
//! was cut or it was issued under another key, does not open.

use iam_domain::CursorSeal;
use rand::Rng as _;
use sha2::{Digest as _, Sha256};

/// The bytes of an HMAC-SHA256 tag.
const TAG_BYTES: usize = 32;

/// The bytes of one block of SHA-256, which is the block size of the HMAC.
const BLOCK_BYTES: usize = 64;

/// The inner and the outer padding bytes of the HMAC (RFC 2104).
const INNER_PAD: u8 = 0x36;
const OUTER_PAD: u8 = 0x5c;

/// The unpadded base64url alphabet (RFC 4648, section 5).
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The bytes of the key that [`HmacCursorSeal::random`] draws.
const RANDOM_KEY_BYTES: usize = 32;

/// Seals cursors with HMAC-SHA256.
pub struct HmacCursorSeal {
    key: Vec<u8>,
}

impl std::fmt::Debug for HmacCursorSeal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HmacCursorSeal")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl HmacCursorSeal {
    /// A seal under `key`: every replica that is configured with the same key opens the cursors of
    /// the others.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    /// A seal under a random key that lives as long as the process: the cursors it issues open
    /// only in this process.
    #[must_use]
    pub fn random() -> Self {
        let mut key = [0_u8; RANDOM_KEY_BYTES];
        rand::rng().fill_bytes(&mut key);
        Self::new(&key)
    }
}

impl CursorSeal for HmacCursorSeal {
    fn seal(&self, payload: &str) -> String {
        let mut token = payload.as_bytes().to_vec();
        token.extend_from_slice(&hmac_sha256(&self.key, payload.as_bytes()));
        encode(&token)
    }

    fn open(&self, token: &str) -> Option<String> {
        let bytes = decode(token)?;
        let (payload, tag) = bytes.split_at_checked(bytes.len().checked_sub(TAG_BYTES)?)?;
        same_bytes(&hmac_sha256(&self.key, payload), tag).then_some(())?;
        String::from_utf8(payload.to_vec()).ok()
    }
}

/// The HMAC-SHA256 of `message` under `key` (RFC 2104): a key longer than a block is hashed first.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; TAG_BYTES] {
    let hashed = Sha256::digest(key);
    let key: &[u8] = if key.len() > BLOCK_BYTES {
        &hashed
    } else {
        key
    };
    let mut block = [0_u8; BLOCK_BYTES];
    for (slot, byte) in block.iter_mut().zip(key) {
        *slot = *byte;
    }
    let inner = Sha256::new()
        .chain_update(block.map(|byte| byte ^ INNER_PAD))
        .chain_update(message)
        .finalize();
    Sha256::new()
        .chain_update(block.map(|byte| byte ^ OUTER_PAD))
        .chain_update(inner)
        .finalize()
        .into()
}

/// Whether the two byte strings are equal, in a time that does not depend on where they differ.
fn same_bytes(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left_byte, right_byte)| {
                difference | (left_byte ^ right_byte)
            })
            == 0
}

/// `bytes` as unpadded base64url.
fn encode(bytes: &[u8]) -> String {
    let mut text = String::new();
    for chunk in bytes.chunks(3) {
        let [first, second, third] = [0, 1, 2].map(|index| chunk.get(index).copied().unwrap_or(0));
        let sextets = [
            first >> 2,
            ((first & 0b11) << 4) | (second >> 4),
            ((second & 0b1111) << 2) | (third >> 6),
            third & 0b11_1111,
        ];
        text.extend(
            sextets
                .iter()
                .take(chunk.len().saturating_add(1))
                .filter_map(|sextet| ALPHABET.get(usize::from(*sextet)))
                .map(|letter| char::from(*letter)),
        );
    }
    text
}

/// The bytes of unpadded base64url `text`; `None` for a character outside the alphabet or a length
/// that no encoding has.
fn decode(text: &str) -> Option<Vec<u8>> {
    let sextets = text
        .bytes()
        .map(|letter| {
            let position = ALPHABET.iter().position(|candidate| *candidate == letter)?;
            u8::try_from(position).ok()
        })
        .collect::<Option<Vec<u8>>>()?;
    let mut bytes = Vec::new();
    for group in sextets.chunks(4) {
        if group.len() == 1 {
            return None;
        }
        let [one, two, three, four] =
            [0, 1, 2, 3].map(|index| group.get(index).copied().unwrap_or(0));
        let decoded = [
            (one << 2) | (two >> 4),
            (two << 4) | (three >> 2),
            (three << 6) | four,
        ];
        bytes.extend(decoded.iter().take(group.len().saturating_sub(1)));
    }
    Some(bytes)
}

#[cfg(test)]
mod tests;
