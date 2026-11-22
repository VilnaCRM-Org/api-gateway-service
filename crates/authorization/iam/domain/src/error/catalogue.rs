//! Domain errors of the permission catalogue: its entries and the rename map of an activation.

use crate::value_object::permission_key::PermissionKeyKind;

/// A catalogue entry whose key is not of the form its entity holds.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidCatalogueEntry {
    /// The key is not of the form the entry holds.
    #[error("This catalogue entry holds {expected} keys only.")]
    KeyKind {
        /// The form the entity holds.
        expected: &'static str,
        /// The form of the key that was given.
        found: PermissionKeyKind,
    },
}

/// A rename map that cannot be built or that does not fit the activation it is applied to.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RenameRefused {
    /// A key is renamed to itself.
    #[error("The key {key} cannot be renamed to itself.")]
    Unchanged {
        /// The key.
        key: String,
    },
    /// The old and the new key differ in service or form, or are reserved keys.
    #[error("The key {from} cannot be renamed to {to}: both must be keys of one service and form.")]
    Scope {
        /// The old key.
        from: String,
        /// The new key.
        to: String,
    },
    /// A key is both an old and a new key of the map.
    #[error("The key {key} cannot be both renamed and the target of a rename.")]
    Chained {
        /// The key.
        key: String,
    },
    /// An old key is renamed twice.
    #[error("The key {key} is renamed more than once.")]
    Duplicate {
        /// The old key.
        key: String,
    },
    /// A key is not of the service and the form of the catalogue.
    #[error("The key {key} does not belong to the catalogue of this service and form.")]
    OutsideCatalogue {
        /// The key.
        key: String,
    },
    /// The new key is not in the catalogue that takes effect.
    #[error("The new key {to} is not in the catalogue.")]
    TargetMissing {
        /// The new key.
        to: String,
    },
    /// The old key is still in the catalogue that takes effect.
    #[error("The old key {from} is still in the catalogue.")]
    SourceStillPresent {
        /// The old key.
        from: String,
    },
}

#[cfg(test)]
mod tests;
