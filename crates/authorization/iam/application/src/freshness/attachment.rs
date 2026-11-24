//! The attachment of a probe proof to a published snapshot (FR-73, ADR 0024).
//!
//! A proof says that at `t_s` the last stable offset of the state partition was `HW(t_s)`. It may
//! be attached only to a snapshot that holds every complete version whose last record lies below
//! that offset. The apply thread keeps one [`ProofAttachment`]: it learns from every record it
//! handles how far the applied versions reach, and from every idle poll of the tail how far the
//! committed log reaches without a record (the commit markers of transactions).

use std::collections::VecDeque;

use iam_domain::freshness::proof::FreshnessProof;

/// How many proofs wait for their snapshot; the oldest is dropped beyond it, as a newer proof
/// supersedes it.
const WAITING_LIMIT: usize = 16;

/// What the apply thread knows about the reach of the applied versions.
#[derive(Debug, Clone, Default)]
pub struct ProofAttachment {
    /// Every offset below this one belongs to a complete applied version or holds no record.
    covered: i64,
    /// The offset after the last record the apply thread handled.
    read_through: i64,
    /// The offset of the first record of the version that is not complete yet.
    pending_from: Option<i64>,
    waiting: VecDeque<FreshnessProof>,
}

impl ProofAttachment {
    /// An attachment for a pod that applied the log below `tail_from` and follows it from there.
    /// The proofs that waited are dropped: they were taken before the state was replaced.
    #[must_use]
    pub const fn starting_at(tail_from: i64) -> Self {
        Self {
            covered: tail_from,
            read_through: tail_from,
            pending_from: None,
            waiting: VecDeque::new(),
        }
    }

    /// The record at `offset` completed a version that was applied.
    pub const fn record_complete(&mut self, offset: i64) {
        self.read_through = offset.saturating_add(1);
        self.pending_from = None;
        self.covered = self.read_through;
    }

    /// The record at `offset` belongs to a version that is not complete yet.
    pub fn record_held(&mut self, offset: i64) {
        self.read_through = offset.saturating_add(1);
        self.pending_from.get_or_insert(offset);
    }

    /// The record at `offset` was dropped as a repeat of what the pod applied.
    pub const fn record_skipped(&mut self, offset: i64) {
        self.read_through = offset.saturating_add(1);
        if self.pending_from.is_none() {
            self.covered = self.read_through;
        }
    }

    /// The tail polled at `position` and found no record before `high`, the last stable offset:
    /// what lies between is commit markers and aborted records. It counts only when the pod has
    /// handled every record before `position` and holds no half version.
    pub fn caught_up(&mut self, position: i64, high: i64) {
        if position == self.read_through && self.pending_from.is_none() {
            self.covered = self.covered.max(high);
        }
    }

    /// A proof waits for the snapshot that covers its watermark.
    pub fn offer(&mut self, proof: FreshnessProof) {
        if self.waiting.len() >= WAITING_LIMIT {
            self.waiting.pop_front();
        }
        self.waiting.push_back(proof);
    }

    /// The newest waiting proof that the applied versions cover; it and every older proof leave
    /// the queue. The caller attaches it only when the published snapshot is the applied one.
    pub fn take_attachable(&mut self) -> Option<FreshnessProof> {
        let covered = self.covered;
        let newest = self
            .waiting
            .iter()
            .filter(|proof| proof.watermark <= covered)
            .max_by_key(|proof| proof.taken_at)
            .copied()?;
        self.waiting
            .retain(|proof| proof.taken_at > newest.taken_at);
        Some(newest)
    }

    /// How many proofs wait.
    #[must_use]
    pub fn waiting(&self) -> usize {
        self.waiting.len()
    }
}

#[cfg(test)]
mod tests;
