//! The name of an upstream.

use crate::error::{InvalidIamValue, InvalidUpstream};
use crate::value_object::service_name::ServiceName;

/// An upstream name: the service-name pattern `^[a-z][a-z0-9]*(-[a-z0-9]+)*$`, at most 63
/// characters. The name is immutable after the upstream is created.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UpstreamName(ServiceName);

impl UpstreamName {
    /// Validates the length and the shape of the name.
    ///
    /// # Errors
    ///
    /// [`InvalidUpstream::NameLength`] when the name is empty or longer than 63 characters and
    /// [`InvalidUpstream::NamePattern`] when it does not match the pattern.
    pub fn new(value: &str) -> Result<Self, InvalidUpstream> {
        ServiceName::new(value).map(Self).map_err(|invalid| {
            if invalid == InvalidIamValue::ServiceNameLength {
                InvalidUpstream::NameLength
            } else {
                InvalidUpstream::NamePattern
            }
        })
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Display for UpstreamName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests;
