//! `OpenAPI` document parser port.

use crate::error::InvalidSpec;
use crate::value_object::rest_operation_set::RestOperationSet;

/// Turns an `OpenAPI` 3.0.x or 3.1.x JSON document into a [`RestOperationSet`].
///
/// The adapter refuses a document over
/// [`OpenApiSpec::MAX_DOCUMENT_BYTES`](crate::OpenApiSpec::MAX_DOCUMENT_BYTES) before it starts
/// parsing, resolves only internal `#/` references and never fetches anything. Parsing is pure
/// computation, so the port is synchronous.
pub trait OpenApiDocumentParser: std::fmt::Debug + Send + Sync {
    /// Parses the document.
    ///
    /// # Errors
    ///
    /// [`InvalidSpec::DocumentTooLarge`] for a document over the byte limit,
    /// [`InvalidSpec::Malformed`] with the JSON pointer of the fault for content that is not a
    /// JSON `OpenAPI` document or holds an external reference,
    /// [`InvalidSpec::TooManyOperations`] for more than
    /// [`RestOperationSet::MAX_OPERATIONS`] operations and [`InvalidSpec::DuplicateOperation`]
    /// for two operations with the same normalised key.
    fn parse(&self, document: &str) -> Result<RestOperationSet, InvalidSpec>;
}
