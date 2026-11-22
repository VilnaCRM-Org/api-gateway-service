//! The unique id of one token (the `jti` claim).

use crate::value_object::text::is_visible_ascii;
use crate::value_object::token_rejection::TokenRejection;

/// The unique id of one token (the `jti` claim). It holds 1 to 255 visible ASCII characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TokenId(String);

impl TokenId {
    /// The largest number of characters.
    pub const MAX_LENGTH: usize = 255;

    /// Validates the claim value.
    ///
    /// # Errors
    ///
    /// Returns [`TokenRejection::Invalid`] when the text is empty, longer than
    /// [`Self::MAX_LENGTH`] or holds a character that is not visible ASCII, because the value comes
    /// from a token and a malformed claim makes the token invalid.
    pub fn new(value: &str) -> Result<Self, TokenRejection> {
        if !is_visible_ascii(value, Self::MAX_LENGTH) {
            return Err(TokenRejection::Invalid);
        }
        Ok(Self(value.to_owned()))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TokenId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests;
