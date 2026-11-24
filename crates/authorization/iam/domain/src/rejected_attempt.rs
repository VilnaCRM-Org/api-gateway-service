//! A refused request of an IAM operation, and the summary that records a run of identical ones
//! (FR-49).
//!
//! A refusal must not cost the request a write to the audit chain, so the refusals are buffered and
//! a loop appends them in batches. Identical refusals (same actor, action and reason) are summarised
//! into one record with a count: the first refusal of a window is due at the next flush, the ones
//! that follow within [`SUMMARY_WINDOW`] are summarised and due when the window ends.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use crate::value_object::actor_ref::ActorRef;
use crate::value_object::audit_action::AuditAction;
use crate::value_object::audit_reason::AuditReason;
use crate::value_object::audit_target::AuditTarget;
use crate::value_object::request_id::RequestId;

/// How long identical refusals are summarised into one record.
pub const SUMMARY_WINDOW: Duration = Duration::from_secs(60);

/// One refused request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedAttempt {
    /// Who made the request.
    pub actor: ActorRef,
    /// What the request tried to do.
    pub action: AuditAction,
    /// Why it was refused.
    pub reason: AuditReason,
    /// What it was aimed at.
    pub target: AuditTarget,
    /// When it was refused, from the `Clock` port.
    pub occurred_at: SystemTime,
    /// The request id of the first refusal.
    pub request_id: Option<RequestId>,
}

/// The refusals of one run of identical attempts: the first of them and how many there were.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptSummary {
    first: RejectedAttempt,
    count: u64,
}

impl AttemptSummary {
    /// A summary of `count` attempts that began with `first`.
    #[must_use]
    pub const fn new(first: RejectedAttempt, count: u64) -> Self {
        Self { first, count }
    }

    /// The first refusal of the run.
    #[must_use]
    pub const fn first(&self) -> &RejectedAttempt {
        &self.first
    }

    /// The number of refusals the summary stands for.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }
}

/// What identical means: the actor, the action and the reason.
type AttemptKey = (ActorRef, AuditAction, AuditReason);

/// The refusals of one key that are not appended yet.
#[derive(Debug)]
struct Slot {
    /// The first pending refusal.
    first: RejectedAttempt,
    /// How many refusals are pending.
    pending: u64,
    /// When the window began.
    window_start: SystemTime,
    /// Whether the window already produced a record.
    emitted: bool,
}

impl Slot {
    fn window_over(&self, at: SystemTime) -> bool {
        self.window_start
            .checked_add(SUMMARY_WINDOW)
            .is_some_and(|end| at >= end)
    }

    /// Whether the pending refusals are due at `now`: the first of a window at once, the others
    /// when the window ends.
    fn due(&self, now: SystemTime) -> bool {
        self.pending > 0 && (!self.emitted || self.window_over(now))
    }

    /// Takes the pending refusals as a summary and starts a new window at `now` when the old one
    /// is over.
    fn take(&mut self, now: SystemTime) -> AttemptSummary {
        let summary = AttemptSummary::new(self.first.clone(), self.pending);
        self.pending = 0;
        if self.window_over(now) {
            self.window_start = now;
        }
        self.emitted = true;
        summary
    }

    /// Whether the slot holds nothing and its window is over, so it can be forgotten.
    fn idle(&self, now: SystemTime) -> bool {
        self.pending == 0 && self.window_over(now)
    }
}

/// The buffer of refusals that were not appended to the audit log yet.
///
/// It is a plain value: the caller supplies the time of every call and owns the lock around it.
#[derive(Debug, Default)]
pub struct RejectedAttemptBuffer {
    slots: HashMap<AttemptKey, Slot>,
}

impl RejectedAttemptBuffer {
    /// An empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The slot of the key of `attempt`, created empty when the key is new.
    fn slot_of(&mut self, attempt: &RejectedAttempt) -> &mut Slot {
        let key = (
            attempt.actor.clone(),
            attempt.action.clone(),
            attempt.reason.clone(),
        );
        self.slots.entry(key).or_insert_with(|| Slot {
            first: attempt.clone(),
            pending: 0,
            window_start: attempt.occurred_at,
            emitted: false,
        })
    }

    /// Adds one refusal to the run of its key.
    pub fn offer(&mut self, attempt: RejectedAttempt) {
        let at = attempt.occurred_at;
        let slot = self.slot_of(&attempt);
        if slot.pending == 0 {
            if slot.window_over(at) {
                slot.window_start = at;
                slot.emitted = false;
            }
            slot.first = attempt;
        }
        slot.pending = slot.pending.saturating_add(1);
    }

    /// Takes the summaries that are due at `now`, oldest first, and forgets the keys that have
    /// been quiet for a window.
    pub fn drain(&mut self, now: SystemTime) -> Vec<AttemptSummary> {
        let mut due = Vec::new();
        self.slots.retain(|_, slot| {
            if slot.due(now) {
                due.push(slot.take(now));
            }
            !slot.idle(now)
        });
        due.sort_by_key(|summary| summary.first().occurred_at);
        due
    }

    /// Puts summaries back that could not be appended, due at the next flush.
    pub fn requeue(&mut self, summaries: Vec<AttemptSummary>) {
        for summary in summaries {
            let AttemptSummary { first, count } = summary;
            let slot = self.slot_of(&first);
            if slot.pending == 0 {
                slot.first = first;
            }
            slot.pending = slot.pending.saturating_add(count);
            slot.emitted = false;
        }
    }

    /// The number of keys the buffer holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether the buffer holds no key.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
}

#[cfg(test)]
mod tests;
