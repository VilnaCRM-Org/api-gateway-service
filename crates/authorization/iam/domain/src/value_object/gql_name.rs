//! A GraphQL type or field name inside a permission key.

/// A GraphQL name (`[_A-Za-z][_0-9A-Za-z]*`) that does not use the reserved `__` prefix, at most
/// 255 characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GqlName(String);

impl GqlName {
    /// The largest number of characters of a name.
    pub const MAX_LENGTH: usize = 255;

    /// Validates the name; `None` when it breaks a rule.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let valid = value.len() <= Self::MAX_LENGTH
            && value.starts_with(|first: char| first == '_' || first.is_ascii_alphabetic())
            && !value.starts_with("__")
            && value
                .bytes()
                .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric());
        valid.then(|| Self(value.to_owned()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for GqlName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests;
