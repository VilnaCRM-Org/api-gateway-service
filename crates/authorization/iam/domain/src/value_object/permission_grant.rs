//! One grant of a role: a key or a wildcard pattern.

use crate::error::InvalidPermissionKey;
use crate::value_object::permission_key::PermissionKey;
use crate::value_object::service_name::ServiceName;
use crate::value_object::wildcard_pattern::WildcardPattern;

/// What a role grants: one exact key, or one of the four wildcard forms.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PermissionGrant {
    /// One exact key, reserved keys included.
    Key(PermissionKey),
    /// A wildcard pattern.
    Wildcard(WildcardPattern),
}

impl PermissionGrant {
    /// Parses a grant: an `iam:` text is a reserved key (so `iam:grant:*` is a key), any other
    /// text that holds a `*` is a wildcard pattern (no key may hold one), and the rest are keys.
    ///
    /// # Errors
    ///
    /// Returns the [`InvalidPermissionKey`] of the key or pattern parser.
    pub fn parse(value: &str) -> Result<Self, InvalidPermissionKey> {
        if !value.starts_with("iam:") && value.contains('*') {
            return WildcardPattern::parse(value).map(Self::Wildcard);
        }
        PermissionKey::parse(value).map(Self::Key)
    }

    /// Whether the grant is a wildcard pattern.
    #[must_use]
    pub const fn is_wildcard(&self) -> bool {
        matches!(self, Self::Wildcard(_))
    }

    /// The service of the key or pattern.
    #[must_use]
    pub fn service(&self) -> &ServiceName {
        match self {
            Self::Key(key) => key.service(),
            Self::Wildcard(pattern) => pattern.service(),
        }
    }
}

impl std::fmt::Display for PermissionGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Key(key) => std::fmt::Display::fmt(key, f),
            Self::Wildcard(pattern) => std::fmt::Display::fmt(pattern, f),
        }
    }
}

#[cfg(test)]
mod tests;
