//! Shared checks of DNS-shaped text.

/// The largest number of characters of a DNS label.
const MAX_LABEL: usize = 63;

/// Whether the text is a lower-case DNS label: 1 to 63 characters of letters, digits and dashes
/// that starts and ends with a letter or a digit.
pub(crate) fn is_label(value: &str) -> bool {
    let edge = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    value.len() <= MAX_LABEL
        && value.bytes().next().is_some_and(edge)
        && value.bytes().next_back().is_some_and(edge)
        && value.bytes().all(|byte| edge(byte) || byte == b'-')
}

#[cfg(test)]
mod tests;
