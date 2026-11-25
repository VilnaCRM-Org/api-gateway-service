//! The request-path side of the access log.

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
        if let Some(item) = self.builder.build(facts) {
            self.channel.offer(item);
        }
    }
}

#[cfg(test)]
mod tests;
