//! The proofs of freshness on the apply thread (Story 9.5, FR-73).
//!
//! The probe task hands its proofs to the thread; the thread attaches one to the published
//! snapshot once the snapshot holds every complete version whose last record lies below the
//! watermark of the proof. It learns how far the applied versions reach from the records it
//! handles, and how far the committed log reaches without a record from the idle polls of the
//! tail, which cover the commit markers behind the last record.

use std::sync::Arc;

use iam_application::{FreshnessState, ProofAttachment};
use iam_domain::PolicyView as _;
use iam_domain::freshness::proof::FreshnessProof;
use iam_infrastructure::{ApplyOutcome, ArcSwapPolicySnapshot, PolicySnapshotBuilder};

/// The state of the proofs on the thread; without a freshness state it does nothing.
#[derive(Debug)]
pub(super) struct Proofs {
    state: Option<Arc<FreshnessState>>,
    attachment: ProofAttachment,
}

impl Proofs {
    pub(super) fn new(state: Option<Arc<FreshnessState>>) -> Self {
        Self {
            state,
            attachment: ProofAttachment::default(),
        }
    }

    /// The state was replaced by the one the bootstrap read; the tail starts at `tail_from`.
    pub(super) fn installed(&mut self, tail_from: i64) {
        self.attachment = ProofAttachment::starting_at(tail_from);
    }

    /// What the builder did with the record at `offset`.
    pub(super) fn record(&mut self, offset: i64, outcome: &ApplyOutcome) {
        match outcome {
            ApplyOutcome::Applied { .. } => self.attachment.record_complete(offset),
            ApplyOutcome::Pending { .. } => self.attachment.record_held(offset),
            ApplyOutcome::Ignored(_) | ApplyOutcome::Duplicate => {
                self.attachment.record_skipped(offset);
            }
            ApplyOutcome::Malformed
            | ApplyOutcome::Gap { .. }
            | ApplyOutcome::Fenced(_)
            | ApplyOutcome::Rejected(_) => {}
        }
    }

    /// The tail polled at `position` and found the committed log at an end, `high`.
    pub(super) fn caught_up(&mut self, position: i64, high: i64) {
        self.attachment.caught_up(position, high);
    }

    /// A proof of the probe waits for the snapshot that covers it.
    pub(super) fn offer(&mut self, proof: FreshnessProof) {
        if self.state.is_some() {
            self.attachment.offer(proof);
        }
    }

    /// Attaches the newest proof that the applied versions cover, when the published snapshot is
    /// the applied one: a snapshot that lags the builder does not hold every applied version.
    pub(super) fn attach(&mut self, builder: &PolicySnapshotBuilder, cell: &ArcSwapPolicySnapshot) {
        let Some(state) = self.state.as_ref() else {
            return;
        };
        let Some(published) = cell.current() else {
            return;
        };
        if published.version() != builder.applied_version() {
            return;
        }
        if let Some(proof) = self.attachment.take_attachable() {
            state.attach(proof, published.version());
        }
    }
}

#[cfg(test)]
mod tests;
