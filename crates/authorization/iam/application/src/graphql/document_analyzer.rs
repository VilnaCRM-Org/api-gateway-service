//! The `async-graphql` adapter of the [`GraphQlDocumentAnalyzer`] port.

mod limits;
mod resolution;

use async_graphql::parser::Positioned;
use async_graphql::parser::parse_query;
use async_graphql::parser::types::{DocumentOperations, ExecutableDocument, OperationDefinition};
use iam_domain::{
    AnalyzedDocument, DocumentLimits, DocumentRefusal, GraphQlDocumentAnalyzer, GraphQlTypeGraph,
    LimitKind,
};

use super::schema_parser::nesting_crossing;

/// The deepest nesting of `[`, `{` and `(` the recursive parser is given; deeper text is refused
/// as over the depth limit before parsing, because the byte limit alone does not bound the
/// parser's stack depth.
const MAX_NESTING: usize = 64;

/// Analyses documents with the parser of `async-graphql`.
///
/// The byte, nesting, fragment, alias, field and depth limits are checked before a field is
/// resolved against the type graph.
#[derive(Debug, Default, Clone, Copy)]
pub struct AsyncGraphQlDocumentAnalyzer;

impl GraphQlDocumentAnalyzer for AsyncGraphQlDocumentAnalyzer {
    fn analyze(
        &self,
        document: &str,
        operation_name: Option<&str>,
        graph: &GraphQlTypeGraph,
        limits: &DocumentLimits,
    ) -> Result<AnalyzedDocument, DocumentRefusal> {
        check_text(document, limits)?;
        let Ok(parsed) = parse_query(document) else {
            return Err(DocumentRefusal::MalformedOperation);
        };
        limits::check_counts(&parsed, limits)?;
        let operation = select_operation(&parsed, operation_name)?;
        limits::check_depth(&parsed, &operation.node, limits)?;
        resolution::resolve(&parsed, &operation.node, graph)
    }
}

/// Refuses text over the byte limit or nested past [`MAX_NESTING`].
fn check_text(document: &str, limits: &DocumentLimits) -> Result<(), DocumentRefusal> {
    if document.len() > limits.bytes {
        return Err(DocumentRefusal::LimitsExceeded(LimitKind::Bytes));
    }
    if nesting_crossing(document, MAX_NESTING).is_some() {
        return Err(DocumentRefusal::LimitsExceeded(LimitKind::Depth));
    }
    Ok(())
}

/// The operation the request runs: the named one, or the only one of an unnamed request.
fn select_operation<'a>(
    document: &'a ExecutableDocument,
    operation_name: Option<&str>,
) -> Result<&'a Positioned<OperationDefinition>, DocumentRefusal> {
    match (&document.operations, operation_name) {
        (DocumentOperations::Single(operation), None) => Some(operation),
        (DocumentOperations::Multiple(operations), Some(name)) => operations.get(name),
        (DocumentOperations::Multiple(operations), None) if operations.len() == 1 => {
            operations.values().next()
        }
        _ => None,
    }
    .ok_or(DocumentRefusal::MalformedOperation)
}

#[cfg(test)]
mod tests;
