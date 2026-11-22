//! The name of a service registered in IAM.

use std::borrow::Cow;

use crate::error::InvalidIamValue;

/// The service that owns IAM's own operations and reserved keys.
static IAM: ServiceName = ServiceName(Cow::Borrowed("iam"));

/// A service name: `^[a-z][a-z0-9]*(-[a-z0-9]+)*$`, at most 63 characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ServiceName(Cow<'static, str>);

impl ServiceName {
    /// The largest number of characters of a name.
    pub const MAX_LENGTH: usize = 63;

    /// Validates the length and the shape of the name.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::ServiceNameLength`] when the name is empty or longer than
    /// [`Self::MAX_LENGTH`], and [`InvalidIamValue::ServiceNamePattern`] when it does not match the
    /// pattern.
    pub fn new(value: &str) -> Result<Self, InvalidIamValue> {
        if value.is_empty() || value.len() > Self::MAX_LENGTH {
            return Err(InvalidIamValue::ServiceNameLength);
        }
        if !has_service_shape(value) {
            return Err(InvalidIamValue::ServiceNamePattern);
        }
        Ok(Self(Cow::Owned(value.to_owned())))
    }

    /// The name `iam`.
    #[must_use]
    pub fn iam() -> &'static Self {
        &IAM
    }

    /// Whether this is the name `iam`.
    #[must_use]
    pub fn is_iam(&self) -> bool {
        self == &IAM
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ServiceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A lower-case letter followed by dash-separated, non-empty runs of lower-case letters and digits.
fn has_service_shape(value: &str) -> bool {
    value.starts_with(|first: char| first.is_ascii_lowercase())
        && value.split('-').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests;
