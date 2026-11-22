//! Shared checks of opaque text values.

/// Whether the text has 1 to `max` bytes, each a visible ASCII character (`!` to `~`).
pub(crate) fn is_visible_ascii(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(|byte| byte.is_ascii_graphic())
}

/// Whether a word of the text is shaped like a JSON Web Token: three non-empty dot-separated
/// base64url segments whose first one starts like an encoded JSON header.
pub(crate) fn holds_token(value: &str) -> bool {
    value.split(is_word_boundary).any(looks_like_token)
}

/// Every character that cannot be part of a base64url token segment or its `.` separator.
const fn is_word_boundary(character: char) -> bool {
    !(character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
}

/// Three non-empty dot-separated segments whose first one starts like an encoded JSON header.
fn looks_like_token(word: &str) -> bool {
    word.starts_with("eyJ")
        && word.split('.').count() == 3
        && word.split('.').all(|segment| !segment.is_empty())
}

#[cfg(test)]
mod tests;
