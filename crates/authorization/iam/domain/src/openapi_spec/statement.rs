//! The write of one `OpenAPI` specification version that a change hands to the unit of work.

use crate::openapi_spec::{OpenApiSpec, OpenApiSpecParts};

/// The insert of a new specification version with its document. A stored version never changes
/// its document or its operations, so no update of them exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenApiSpecStatement {
    spec: OpenApiSpecParts,
    document: String,
}

impl OpenApiSpecStatement {
    /// The insert of a new version and its document; the storage computes the SHA-256 hash of the
    /// document and refuses the insert when it differs from the hash of the version. A stored
    /// version with the same identifier, or of the same service with the same hash, refuses it as a
    /// duplicate.
    #[must_use]
    pub fn insert(spec: &OpenApiSpec, document: String) -> Self {
        Self {
            spec: spec.parts().clone(),
            document,
        }
    }

    /// The state of the version to store.
    #[must_use]
    pub const fn spec(&self) -> &OpenApiSpecParts {
        &self.spec
    }

    /// The document to store.
    #[must_use]
    pub fn document(&self) -> &str {
        &self.document
    }
}

#[cfg(test)]
mod tests;
