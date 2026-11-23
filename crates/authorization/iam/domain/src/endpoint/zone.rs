//! The availability zone of an upstream endpoint or of the gateway pod.

/// A zone label is not 1 to 63 ASCII letters, digits, `-`, `_` or `.`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a zone must contain 1 to 63 ASCII letters, digits, '-', '_' or '.'")]
pub struct InvalidZone;

/// An availability zone, such as `eu-central-1a`: the value of the Kubernetes `zone` of an
/// endpoint, compared exactly.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Zone(String);

impl Zone {
    /// Validates the length and the characters of the zone.
    ///
    /// # Errors
    ///
    /// [`InvalidZone`] when it is empty, longer than 63 characters or holds another character.
    pub fn new(value: &str) -> Result<Self, InvalidZone> {
        let valid_length = (1..=63).contains(&value.len());
        let valid_characters = value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
        if valid_length && valid_characters {
            Ok(Self(value.to_owned()))
        } else {
            Err(InvalidZone)
        }
    }

    /// The zone.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Zone {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests;
