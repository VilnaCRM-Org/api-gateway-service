//! The cell that holds the published policy snapshot and hands it to readers (FR-71).

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::ThreadId;

use arc_swap::ArcSwapOption;
use iam_domain::{PolicySnapshot, PolicyView};

use super::data::SnapshotData;

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The published snapshot behind an atomic pointer: a reader takes the current `Arc` without a
/// lock and keeps reading that version however many are published meanwhile.
///
/// A cell made with [`deferred`](Self::deferred) keeps every replaced snapshot in a queue until
/// [`reclaim`](Self::reclaim) finds its strong count at 1, so the destructor of a replaced
/// generation never runs on a request task: it runs where `reclaim` is called, which is the apply
/// thread.
#[derive(Debug, Default)]
pub struct ArcSwapPolicySnapshot {
    current: ArcSwapOption<SnapshotData>,
    deferred: bool,
    retired: Mutex<Vec<Arc<SnapshotData>>>,
    reclaimed_on: Mutex<Option<ThreadId>>,
}

impl ArcSwapPolicySnapshot {
    /// A cell with no snapshot published; a replaced snapshot is dropped by the publication.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A cell with no snapshot published that queues the replaced snapshots for
    /// [`reclaim`](Self::reclaim).
    #[must_use]
    pub fn deferred() -> Self {
        Self {
            deferred: true,
            ..Self::default()
        }
    }

    pub(super) fn publish(&self, snapshot: Arc<SnapshotData>) {
        let replaced = self.current.swap(Some(snapshot));
        if let Some(replaced) = replaced.filter(|_snapshot| self.deferred) {
            locked(&self.retired).push(replaced);
        }
    }

    /// Withdraws the published snapshot: readers see no snapshot until the next publication, so
    /// the gateway answers `iam_stale`. The withdrawn snapshot is retired like a replaced one.
    pub fn clear(&self) {
        let withdrawn = self.current.swap(None);
        if let Some(withdrawn) = withdrawn.filter(|_snapshot| self.deferred) {
            locked(&self.retired).push(withdrawn);
        }
    }

    /// Frees the retired snapshots that no reader holds any more (strong count 1) on the calling
    /// thread and returns how many it freed; a snapshot a request still reads stays queued.
    pub fn reclaim(&self) -> usize {
        let free = {
            let mut retired = locked(&self.retired);
            let (free, held): (Vec<_>, Vec<_>) = std::mem::take(&mut *retired)
                .into_iter()
                .partition(|snapshot| Arc::strong_count(snapshot) == 1);
            // Recorded while the queue is still locked, so that whoever sees the queue shrink
            // also sees the thread that frees what left it.
            if !free.is_empty() {
                *locked(&self.reclaimed_on) = Some(std::thread::current().id());
            }
            *retired = held;
            free
        };
        let freed = free.len();
        drop(free);
        freed
    }

    /// How many replaced snapshots wait to be reclaimed.
    #[must_use]
    pub fn retired(&self) -> usize {
        locked(&self.retired).len()
    }

    /// The thread on which the last retired snapshot was freed: the test hook that shows where
    /// the destructors run.
    #[must_use]
    pub fn last_reclaimed_on(&self) -> Option<ThreadId> {
        *locked(&self.reclaimed_on)
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
