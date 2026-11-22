//! The raw bearer credential a caller presents.

/// An opaque bearer credential, such as a compact JWS.
///
/// The raw text exists only in request memory: `Debug` prints the type name alone, the type has no
/// `Display`, and the text is read only through [`Self::expose`] by the verifier.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential(String);

impl Credential {
    /// Wraps the raw text as presented, which may be empty.
    #[must_use]
    pub const fn new(value: String) -> Self {
        Self(value)
    }

    /// Whether the caller presented nothing but blanks.
    #[must_use]
    pub fn is_blank(&self) -> bool {
        self.0.trim().is_empty()
    }

    /// The raw text, for the verifier only; never log or format it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credential")
    }
}

#[cfg(test)]
mod tests;
