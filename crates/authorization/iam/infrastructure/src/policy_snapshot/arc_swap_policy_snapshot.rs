//! The cell that holds the published policy snapshot and hands it to readers (FR-71).

use std::sync::Arc;

use arc_swap::ArcSwapOption;
use iam_domain::{PolicySnapshot, PolicyView};

use super::data::SnapshotData;

/// The published snapshot behind an atomic pointer: a reader takes the current `Arc` without a
/// lock and keeps reading that version however many are published meanwhile.
#[derive(Debug, Default)]
pub struct ArcSwapPolicySnapshot {
    current: ArcSwapOption<SnapshotData>,
}

impl ArcSwapPolicySnapshot {
    /// A cell with no snapshot published.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub(super) fn publish(&self, snapshot: Arc<SnapshotData>) {
        self.current.store(Some(snapshot));
    }

    pub(super) fn load(&self) -> Option<Arc<SnapshotData>> {
        self.current.load_full()
    }
}

impl PolicyView for ArcSwapPolicySnapshot {
    fn current(&self) -> Option<Arc<dyn PolicySnapshot>> {
        self.load()
            .map(|snapshot| -> Arc<dyn PolicySnapshot> { snapshot })
    }
}

#[cfg(test)]
mod tests;
