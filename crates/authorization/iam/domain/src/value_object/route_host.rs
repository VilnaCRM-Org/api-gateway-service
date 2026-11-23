//! The host a route serves.

use crate::error::InvalidRoute;
use crate::value_object::dns::is_label;

/// A route host: a lower-case DNS name of dot-separated labels, at most 253 characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RouteHost(String);

impl RouteHost {
    /// The largest number of characters of a host.
    pub const MAX_LENGTH: usize = 253;

    /// Validates the length and the labels of the host.
    ///
    /// # Errors
    ///
    /// [`InvalidRoute::HostLength`] when the host is empty or longer than [`Self::MAX_LENGTH`] and
    /// [`InvalidRoute::HostFormat`] when a label is empty, upper-case or holds another character
    /// than letters, digits and dashes.
    pub fn new(value: &str) -> Result<Self, InvalidRoute> {
        if value.is_empty() || value.len() > Self::MAX_LENGTH {
            return Err(InvalidRoute::HostLength);
        }
        if !value.split('.').all(is_label) {
            return Err(InvalidRoute::HostFormat);
        }
        Ok(Self(value.to_owned()))
    }

    /// The host.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RouteHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests;
