//! Normalisation of a request path: one percent-decoding, strict path rules (FR-7).

use crate::value_object::decision_reason::DecisionReason;
use crate::value_object::normalized_path::NormalizedPath;

/// Why a request path cannot be read; every variant is the reason code `malformed_operation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MalformedPath {
    /// The path does not start with `/`.
    #[error("The path must start with a slash.")]
    MissingLeadingSlash,
    /// The path is longer than [`PathNormalizer::MAX_BYTES`].
    #[error("The path must contain 2048 bytes or fewer.")]
    TooLong,
    /// A percent escape is not followed by two hexadecimal digits, or the decoded bytes are not
    /// UTF-8.
    #[error("The path holds a malformed percent-encoding.")]
    InvalidEncoding,
    /// A segment is `.` or `..`, written plainly or percent-encoded.
    #[error("The path must not contain dot segments.")]
    DotSegment,
    /// A segment holds, after one decoding, a `/`, a `\`, a `%` or a control character such as NUL.
    #[error("The path holds a character that is not allowed.")]
    ForbiddenCharacter,
}

impl From<MalformedPath> for DecisionReason {
    /// Every malformed path is the reason code `malformed_operation`.
    fn from(_: MalformedPath) -> Self {
        Self::MalformedOperation
    }
}

/// Turns the raw path of a request into a [`NormalizedPath`].
///
/// The query is ignored, repeated and trailing slashes vanish, and each segment is
/// percent-decoded exactly once. A `%` left after that decoding is refused, so a double-encoded sequence never decodes a second time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PathNormalizer;

impl PathNormalizer {
    /// The largest number of bytes of the path, before decoding.
    pub const MAX_BYTES: usize = 2_048;

    /// Normalises `target`, a path with an optional `?query`.
    ///
    /// # Errors
    ///
    /// The [`MalformedPath`] variant that names the first broken rule.
    pub fn normalize(target: &str) -> Result<NormalizedPath, MalformedPath> {
        let path = target.split_once('?').map_or(target, |(path, _)| path);
        if !path.starts_with('/') {
            return Err(MalformedPath::MissingLeadingSlash);
        }
        if path.len() > Self::MAX_BYTES {
            return Err(MalformedPath::TooLong);
        }
        path.split('/')
            .filter(|segment| !segment.is_empty())
            .map(decode_segment)
            .collect::<Result<Vec<_>, _>>()
            .map(NormalizedPath::from_segments)
    }
}

fn decode_segment(raw: &str) -> Result<String, MalformedPath> {
    let decoded = percent_decode(raw).ok_or(MalformedPath::InvalidEncoding)?;
    if decoded == "." || decoded == ".." {
        return Err(MalformedPath::DotSegment);
    }
    if decoded.chars().any(is_forbidden) {
        return Err(MalformedPath::ForbiddenCharacter);
    }
    Ok(decoded)
}

const fn is_forbidden(character: char) -> bool {
    character.is_control() || matches!(character, '/' | '\\' | '%')
}

/// Decodes `%XX` escapes once; `None` for a truncated or non-hexadecimal escape or non-UTF-8 bytes.
fn percent_decode(raw: &str) -> Option<String> {
    let mut decoded = Vec::with_capacity(raw.len());
    let mut bytes = raw.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let high = hex_value(bytes.next()?)?;
            let low = hex_value(bytes.next()?)?;
            decoded.push(high.checked_mul(16)?.checked_add(low)?);
        } else {
            decoded.push(byte);
        }
    }
    String::from_utf8(decoded).ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    char::from(byte)
        .to_digit(16)
        .and_then(|digit| u8::try_from(digit).ok())
}

#[cfg(test)]
mod tests;
