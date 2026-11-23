//! The coordinates a GraphQL document touches.

use crate::value_object::coordinate_set::CoordinateSet;

/// The result of analysing a document: the `{Type}.{field}` coordinates it selects and whether it
/// reads the schema through `__schema` or `__type`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnalyzedDocument {
    coordinates: CoordinateSet,
    introspection: bool,
}

impl AnalyzedDocument {
    /// A result of `coordinates` and the introspection flag.
    #[must_use]
    pub const fn new(coordinates: CoordinateSet, introspection: bool) -> Self {
        Self {
            coordinates,
            introspection,
        }
    }

    /// The selected coordinates, `__typename` excluded.
    #[must_use]
    pub const fn coordinates(&self) -> &CoordinateSet {
        &self.coordinates
    }

    /// Whether the document selects `__schema` or `__type`, which the key
    /// `gql:{service}:__introspection` guards.
    #[must_use]
    pub const fn introspection(&self) -> bool {
        self.introspection
    }
}

#[cfg(test)]
mod tests;
