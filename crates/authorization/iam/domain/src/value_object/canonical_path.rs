//! The re-encoded path that the gateway forwards to an upstream.

/// A path in its canonical wire form: a leading `/`, no trailing slash, no empty segment, and
/// every byte of a segment outside the unreserved set (`A-Z a-z 0-9 - . _ ~`) written as an
/// upper-case `%XX` escape.
///
/// Decoding it once returns exactly the [`NormalizedPath`](super::normalized_path::NormalizedPath)
/// that was matched, so the upstream decodes the bytes that were authorised.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CanonicalPath(String);

impl CanonicalPath {
    /// Encodes decoded segments; no segments is the root path `/`.
    pub(crate) fn encode(segments: &[String]) -> Self {
        let mut encoded = String::new();
        for segment in segments {
            encoded.push('/');
            for byte in segment.bytes() {
                push_byte(&mut encoded, byte);
            }
        }
        if encoded.is_empty() {
            encoded.push('/');
        }
        Self(encoded)
    }

    /// The canonical path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn push_byte(encoded: &mut String, byte: u8) {
    if is_unreserved(byte) {
        encoded.push(char::from(byte));
    } else {
        encoded.push('%');
        encoded.push(hex_digit(byte >> 4));
        encoded.push(hex_digit(byte & 0x0F));
    }
}

const fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn hex_digit(nibble: u8) -> char {
    char::from_digit(u32::from(nibble), 16).map_or('0', |digit| digit.to_ascii_uppercase())
}

impl std::fmt::Display for CanonicalPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests;
