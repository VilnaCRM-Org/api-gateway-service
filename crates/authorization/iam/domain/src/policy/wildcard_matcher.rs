//! Fixed-probe matching of a permission key against the four wildcard forms of FR-10.

use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_key::{GqlCoordinate, PermissionKey};
use crate::value_object::wildcard_pattern::WildcardPattern;

/// Derives, for a key, the at most two wildcard patterns that cover it, so a lookup never scans
/// the wildcards of a role. A sensitive key and a reserved key are covered by no wildcard.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WildcardMatcher;

impl WildcardMatcher {
    /// The patterns that cover `key`, narrowest first: `rest:{s}:{METHOD} *` then `rest:{s}:*`
    /// for a REST key, `gql:{s}:{Type}.*` then `gql:{s}:*` for a field, `gql:{s}:*` for
    /// introspection, and none for a reserved or sensitive key.
    #[must_use]
    pub fn probes(key: &PermissionKey, flags: PermissionFlags) -> Vec<WildcardPattern> {
        if flags.is_sensitive() {
            return Vec::new();
        }
        match key {
            PermissionKey::Rest {
                service, method, ..
            } => vec![
                WildcardPattern::RestMethod {
                    service: service.clone(),
                    method: *method,
                },
                WildcardPattern::RestService {
                    service: service.clone(),
                },
            ],
            PermissionKey::Gql {
                service,
                coordinate: GqlCoordinate::Field { type_name, .. },
            } => vec![
                WildcardPattern::GqlType {
                    service: service.clone(),
                    type_name: type_name.clone(),
                },
                WildcardPattern::GqlService {
                    service: service.clone(),
                },
            ],
            PermissionKey::Gql {
                service,
                coordinate: GqlCoordinate::Introspection,
            } => vec![WildcardPattern::GqlService {
                service: service.clone(),
            }],
            PermissionKey::Reserved(_) => Vec::new(),
        }
    }

    /// Whether `pattern` covers `key` with the catalogue `flags` of the key.
    #[must_use]
    pub fn covers(pattern: &WildcardPattern, key: &PermissionKey, flags: PermissionFlags) -> bool {
        Self::probes(key, flags).contains(pattern)
    }
}

#[cfg(test)]
mod tests;
