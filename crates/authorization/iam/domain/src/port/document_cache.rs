//! Port of the cache of analysed GraphQL documents (FR-8).

use crate::value_object::analyzed_document::AnalyzedDocument;
use crate::value_object::document_key::DocumentKey;
use crate::value_object::service_name::ServiceName;

/// Remembers what analysing a document found, so that the same document of the same service under
/// the same catalogue is not parsed twice.
///
/// A value is the coordinate set and the introspection flag of the analysis, never a decision: who
/// may do what is decided again for every request. Hits are counted only after the stored text
/// equals the requested one in full ([`DocumentKey::confirms`]), so two documents that collide on
/// the hash never share an entry. The cache is a pure in-memory structure, so the port is
/// synchronous.
pub trait DocumentCache: std::fmt::Debug + Send + Sync {
    /// The analysis stored for `document` of `service` under `key`, when the stored text is the
    /// requested one.
    fn get(
        &self,
        service: &ServiceName,
        key: DocumentKey,
        document: &str,
    ) -> Option<AnalyzedDocument>;

    /// Stores the analysis of `document`, replacing the entry of an equal key.
    fn insert(
        &self,
        service: &ServiceName,
        key: DocumentKey,
        document: &str,
        analyzed: AnalyzedDocument,
    );
}
