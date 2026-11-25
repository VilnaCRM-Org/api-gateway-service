//! [`DocumentCache`] backed by a bounded `moka` cache (Story 10.8).

use std::time::Duration;

use iam_domain::{AnalyzedDocument, DocumentCache, DocumentKey, ServiceName};

/// What each coordinate of a stored analysis is counted as, in bytes, besides its document text.
const COORDINATE_WEIGHT: usize = 96;

/// The size and idle lifetime of the cache (`GRAPHQL_DOCUMENT_CACHE_BYTES`,
/// `GRAPHQL_DOCUMENT_CACHE_IDLE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocumentCacheSettings {
    /// The weight the cache may hold: the bytes of the stored documents plus a fixed weight per
    /// coordinate.
    pub capacity_bytes: u64,
    /// How long an entry that nobody asks for stays.
    pub time_to_idle: Duration,
}

/// A stored analysis with the text it was made for.
#[derive(Debug, Clone)]
struct Stored {
    document: String,
    analyzed: AnalyzedDocument,
}

/// The analyses of the documents that requests sent, by service and [`DocumentKey`].
///
/// A value is a coordinate set and an introspection flag, never a decision, so a change of policy
/// needs no invalidation; a change of the catalogue is in the key through its version. A hit
/// needs the stored text to equal the requested one in full, so a collision of two hashes serves
/// neither document the other's analysis.
#[derive(Debug)]
pub struct MokaDocumentCache {
    entries: moka::sync::Cache<(ServiceName, DocumentKey), Stored>,
}

impl MokaDocumentCache {
    /// An empty cache.
    #[must_use]
    pub fn new(settings: DocumentCacheSettings) -> Self {
        let entries = moka::sync::Cache::builder()
            .max_capacity(settings.capacity_bytes)
            .time_to_idle(settings.time_to_idle)
            .weigher(|_key, stored: &Stored| weight(stored))
            .build();
        Self { entries }
    }

    /// The number of entries, after the pending maintenance has run.
    #[must_use]
    pub fn entry_count(&self) -> u64 {
        self.entries.run_pending_tasks();
        self.entries.entry_count()
    }
}

fn weight(stored: &Stored) -> u32 {
    let coordinates = stored.analyzed.coordinates().len();
    let bytes = stored
        .document
        .len()
        .saturating_add(coordinates.saturating_mul(COORDINATE_WEIGHT));
    u32::try_from(bytes).unwrap_or(u32::MAX)
}

impl DocumentCache for MokaDocumentCache {
    fn get(
        &self,
        service: &ServiceName,
        key: DocumentKey,
        document: &str,
    ) -> Option<AnalyzedDocument> {
        let stored = self.entries.get(&(service.clone(), key))?;
        key.confirms(key, &stored.document, document)
            .then_some(stored.analyzed)
    }

    fn insert(
        &self,
        service: &ServiceName,
        key: DocumentKey,
        document: &str,
        analyzed: AnalyzedDocument,
    ) {
        self.entries.insert(
            (service.clone(), key),
            Stored {
                document: document.to_owned(),
                analyzed,
            },
        );
    }
}

#[cfg(test)]
mod tests;
