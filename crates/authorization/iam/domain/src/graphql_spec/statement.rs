//! The write of one specification version that a change hands to the unit of work.

use crate::graphql_spec::{GraphQlSpec, GraphQlSpecParts};

/// The insert of a new specification version with its SDL. A stored version never changes its SDL
/// or its coordinates, so no update of them exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphQlSpecStatement {
    spec: GraphQlSpecParts,
    sdl: String,
}

impl GraphQlSpecStatement {
    /// The insert of a new version and its SDL; the storage computes the SHA-256 hash of the SDL
    /// and refuses the insert when it differs from the hash of the version. A stored version with
    /// the same identifier, or of the same service with the same hash, refuses it as a duplicate.
    #[must_use]
    pub fn insert(spec: &GraphQlSpec, sdl: String) -> Self {
        Self {
            spec: spec.parts().clone(),
            sdl,
        }
    }

    /// The state of the version to store.
    #[must_use]
    pub const fn spec(&self) -> &GraphQlSpecParts {
        &self.spec
    }

    /// The SDL document to store.
    #[must_use]
    pub fn sdl(&self) -> &str {
        &self.sdl
    }
}

#[cfg(test)]
mod tests;
