//! The bounded channel between the request path and the writer thread (FR-50, NFR-24).

use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::time::Duration;

use iam_domain::AccessLane;

use super::audit_gate::AuditGate;
use super::builder::AccessItem;
use super::counters::AccessLogCounters;

/// The sending side, held by the request path.
///
/// [`Self::offer`] never waits: a full channel drops the record and counts the drop by lane and
/// class, and no decision changes.
#[derive(Debug, Clone)]
pub struct AccessLogChannel {
    sender: SyncSender<AccessItem>,
    counters: Arc<AccessLogCounters>,
    audit_gate: Option<Arc<AuditGate>>,
}

/// The receiving side, owned by the writer thread.
#[derive(Debug)]
pub struct AccessLogReceiver {
    receiver: Receiver<AccessItem>,
}

/// A channel of `capacity` records whose drops are counted in `counters`.
#[must_use]
pub fn access_log_channel(
    capacity: usize,
    counters: Arc<AccessLogCounters>,
) -> (AccessLogChannel, AccessLogReceiver) {
    let (sender, receiver) = mpsc::sync_channel(capacity);
    (
        AccessLogChannel {
            sender,
            counters,
            audit_gate: None,
        },
        AccessLogReceiver { receiver },
    )
}

impl AccessLogChannel {
    /// The same channel, which marks `gate` full whenever it drops a record of the audit lane, so
    /// that audit-or-deny refuses the operations that depend on such a record (Story 14.2).
    #[must_use]
    pub fn with_audit_gate(mut self, gate: Arc<AuditGate>) -> Self {
        self.audit_gate = Some(gate);
        self
    }

    /// Hands `item` to the writer without waiting; a full channel, or a writer that is gone, drops
    /// it and counts the drop.
    pub fn offer(&self, item: AccessItem) {
        match self.sender.try_send(item) {
            Ok(()) => {}
            Err(TrySendError::Full(item) | TrySendError::Disconnected(item)) => {
                self.counters.dropped(item.lane, item.class);
                self.mark_full(item.lane);
            }
        }
    }

    /// Marks the audit gate full after a drop of the audit lane. The dropped item gives back its
    /// own slot, if it holds one, when it goes out of scope; a record without a slot releases
    /// nothing.
    fn mark_full(&self, lane: AccessLane) {
        if lane != AccessLane::Audit {
            return;
        }
        if let Some(gate) = self.audit_gate.as_ref() {
            gate.mark_channel_full();
        }
    }
}

/// What waiting for the next item found.
#[derive(Debug, PartialEq, Eq)]
pub enum Received {
    /// The next item.
    Item(Box<AccessItem>),
    /// Nothing arrived within the timeout.
    Idle,
    /// Every sender is gone and the channel is empty.
    Closed,
}

impl AccessLogReceiver {
    /// Waits up to `timeout` for the next item.
    #[must_use]
    pub fn receive(&self, timeout: Duration) -> Received {
        match self.receiver.recv_timeout(timeout) {
            Ok(item) => Received::Item(Box::new(item)),
            Err(RecvTimeoutError::Timeout) => Received::Idle,
            Err(RecvTimeoutError::Disconnected) => Received::Closed,
        }
    }

    /// The next item that is already queued, without waiting.
    #[must_use]
    pub fn try_next(&self) -> Option<AccessItem> {
        self.receiver.try_recv().ok()
    }
}

#[cfg(test)]
mod tests;
