//! A [`DocumentCache`] in a map, for the tests of the use cases that analyse documents.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use iam_domain::{AnalyzedDocument, DocumentCache, DocumentKey, ServiceName};

/// The stored text and analysis of a document, by service and digest.
type Entries = HashMap<(String, u128), (String, AnalyzedDocument)>;

/// Remembers every analysis for ever, keyed like the production cache.
#[derive(Debug, Default)]
pub(crate) struct MapDocumentCache {
    entries: Mutex<Entries>,
}

impl MapDocumentCache {
    /// The number of stored analyses.
    pub(crate) fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

impl DocumentCache for MapDocumentCache {
    fn get(
        &self,
        service: &ServiceName,
        key: DocumentKey,
        document: &str,
    ) -> Option<AnalyzedDocument> {
        let found = self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(service.to_string(), key.digest()))
            .cloned();
        let (stored, analyzed) = found?;
        key.confirms(key, &stored, document).then_some(analyzed)
    }

    fn insert(
        &self,
        service: &ServiceName,
        key: DocumentKey,
        document: &str,
        analyzed: AnalyzedDocument,
    ) {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                (service.to_string(), key.digest()),
                (document.to_owned(), analyzed),
            );
    }
}
