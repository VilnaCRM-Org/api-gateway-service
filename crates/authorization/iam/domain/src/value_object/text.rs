//! Shared checks of opaque text values.

/// Whether the text has 1 to `max` bytes, each a visible ASCII character (`!` to `~`).
pub(crate) fn is_visible_ascii(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(|byte| byte.is_ascii_graphic())
}

#[cfg(test)]
mod tests;
