//! The request-path side of the access log.

use super::audit_gate::AuditSlot;
use super::builder::AccessRecordBuilder;
use super::channel::AccessLogChannel;
use super::facts::AccessFacts;

/// Builds the access record of a decision and hands it to the writer without waiting.
#[derive(Debug)]
pub struct AccessRecorder {
    builder: AccessRecordBuilder,
    channel: AccessLogChannel,
}

impl AccessRecorder {
    /// A recorder that builds with `builder` and sends through `channel`.
    #[must_use]
    pub const fn new(builder: AccessRecordBuilder, channel: AccessLogChannel) -> Self {
        Self { builder, channel }
    }

    /// Records one decision: the record is built, sampled and offered to the channel. The call
    /// never waits and never fails, so it cannot change the decision.
    pub fn record(&self, facts: AccessFacts) {
        self.record_with_slot(facts, None);
    }

    /// Records one decision whose request reserved `slot` for it (audit-or-deny). The item carries
    /// the slot to the writer; a record that is not built gives the slot back at once.
    pub fn record_with_slot(&self, facts: AccessFacts, slot: Option<AuditSlot>) {
        if let Some(item) = self.builder.build(facts) {
            self.channel.offer(item.with_slot(slot));
        }
    }
}

#[cfg(test)]
mod tests;
