//! GraphQL document analyzer port.

use crate::value_object::analyzed_document::AnalyzedDocument;
use crate::value_object::document_limits::DocumentLimits;
use crate::value_object::document_refusal::DocumentRefusal;
use crate::value_object::graphql_type_graph::GraphQlTypeGraph;

/// Reduces a GraphQL document to the schema coordinates it touches.
///
/// The adapter checks `limits` before it resolves anything against `graph`. Analysis is pure
/// computation, so the port is synchronous.
pub trait GraphQlDocumentAnalyzer: std::fmt::Debug + Send + Sync {
    /// Analyses the document for the operation `operation_name` (the only operation when `None`).
    ///
    /// # Errors
    ///
    /// [`DocumentRefusal::LimitsExceeded`] for a document over a limit,
    /// [`DocumentRefusal::MalformedOperation`] for a document that does not parse, does not
    /// validate against `graph` or names a missing or unknown operation, and
    /// [`DocumentRefusal::UnknownOperation`] for a field that `graph` does not declare.
    fn analyze(
        &self,
        document: &str,
        operation_name: Option<&str>,
        graph: &GraphQlTypeGraph,
        limits: &DocumentLimits,
    ) -> Result<AnalyzedDocument, DocumentRefusal>;
}
